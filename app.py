from dotenv import load_dotenv
load_dotenv()

import os
from flask import Flask, Blueprint, render_template, url_for, redirect
from flask_assets import Bundle, Environment
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config["ASSETS_DEBUG"] = True

########## Database

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    osu_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)

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
    return render_template("index.html")

@app.route("/login")
def login():
    redirect_uri = url_for("authorize", _external=True)
    return oauth.osu.authorize_redirect(redirect_uri)

@app.route("/authorize")
def authorize():
    token = oauth.osu.authorize_access_token()
    resp = oauth.osu.get("me")
    resp.raise_for_status()
    profile = resp.json()
    print(profile)
    return redirect("/")

######### API

tourn = Blueprint(__name__, "tourn")
app.register_blueprint(tourn)

@tourn.route("/")
def tindex():
    return "hellosu"
