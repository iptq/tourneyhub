from dotenv import load_dotenv
load_dotenv()

import os
import enum
from datetime import datetime, timedelta
from flask import Flask, Blueprint, render_template, url_for, redirect, jsonify
from flask_assets import Bundle, Environment
from flask_login import LoginManager, login_user, logout_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["ASSETS_DEBUG"] = True

########## Types

class TournStatus(enum.Enum):
    Announced = 0
    RegOpen = 1
    RegClosed = 2
    Running = 3
    Completed = 4

########## Database

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    __tablename__ = "users"
    osu_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    osu_rank = db.Column(db.Integer)

    osu_access_token = db.Column(db.String)
    osu_token_expiry = db.Column(db.DateTime)
    osu_refresh_token = db.Column(db.String)

    is_active = True
    is_authenticated = True
    def get_id(self): return str(self.osu_id)

class Tournament(db.Model):
    __tablename__ = "tournaments"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.osu_id"), nullable=False)
    name = db.Column(db.Unicode)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

    min_rank = db.Column(db.Integer, index=True)
    max_rank = db.Column(db.Integer, index=True)
    country = db.Column(db.String, index=True)

########## Login

login_manager = LoginManager(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(osu_id=user_id).first()

########## Oauth

oauth = OAuth(app)
oauth.register(
    name="osu",
    client_id=os.getenv("OAUTH_CLIENT_ID"),
    client_secret=os.getenv("OAUTH_CLIENT_SECRET"),
    access_token_url="https://osu.ppy.sh/oauth/token",
    access_token_params=None,
    authorize_url="https://osu.ppy.sh/oauth/authorize",
    authorize_params=None,
    api_base_url="https://osu.ppy.sh/api/v2/",
    client_kwargs={"scope": "identify public"},
)

########## Assets

assets = Environment(app)
assets.debug = True
css = Bundle("src/main.css", output="dist/main.css", filters="postcss")
js = Bundle("src/*.js", output="dist/main.js")
assets.register("css", css)
assets.register("js", js)
css.build()
js.build()

########## Routes

@app.route("/")
def index():
    tournaments = Tournament.query.all()
    return render_template("index.html", tournaments=tournaments)

@app.route("/login")
def login():
    redirect_uri = url_for("authorize", _external=True)
    return oauth.osu.authorize_redirect(redirect_uri)

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")

@app.route("/authorize")
def authorize():
    token = oauth.osu.authorize_access_token()
    print(token)
    resp = oauth.osu.get("me")
    resp.raise_for_status()
    profile = resp.json()

    expires_in = token["expires_in"]
    expire_time = datetime.utcnow() + timedelta(seconds = expires_in)
    access_token = token["access_token"]
    refresh_token = token["refresh_token"]

    user = User.query.filter_by(osu_id=profile["id"]).first()
    if not user:
        user = User(osu_id=profile["id"], username=profile["username"], osu_rank=profile["statistics"]["global_rank"])
    user.osu_access_token = access_token
    user.osu_refresh_token = refresh_token
    user.osu_token_expiry = expire_time
    db.session.add(user)
    db.session.commit()

    login_user(user)
    return redirect("/")

######### API

t = Blueprint("t", __name__)

@t.route("/")
def tindex():
    tournaments = Tournament.query.all()
    return jsonify(list(map(lambda t: {}, tournaments)))

@t.route("/create", methods=["GET", "POST"])
def tcreate():
    return render_template("create.html")

app.register_blueprint(t, url_prefix="/t")
