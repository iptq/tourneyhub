"""empty message

Revision ID: 0541385bbfc1
Revises: 
Create Date: 2021-04-21 00:42:21.724255

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0541385bbfc1'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('beatmaps',
    sa.Column('bid', sa.Integer(), nullable=False),
    sa.Column('bsid', sa.Integer(), nullable=False),
    sa.Column('artist', sa.Unicode(), nullable=True),
    sa.Column('title', sa.Unicode(), nullable=True),
    sa.PrimaryKeyConstraint('bid')
    )
    op.create_table('users',
    sa.Column('osu_id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(), nullable=True),
    sa.Column('osu_rank', sa.Integer(), nullable=True),
    sa.Column('osu_access_token', sa.String(), nullable=True),
    sa.Column('osu_token_expiry', sa.DateTime(), nullable=True),
    sa.Column('osu_refresh_token', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('osu_id')
    )
    op.create_table('pooled_beatmaps',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('bid', sa.Integer(), nullable=True),
    sa.Column('mods', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['bid'], ['beatmaps.bid'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('tournaments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('owner_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.Unicode(), nullable=False),
    sa.Column('status', sa.Enum('Pending', 'Announced', 'RegOpen', 'RegClosed', 'Running', 'Completed', name='tournstatus'), nullable=False),
    sa.Column('last_updated', sa.DateTime(), nullable=True),
    sa.Column('min_rank', sa.Integer(), nullable=True),
    sa.Column('max_rank', sa.Integer(), nullable=True),
    sa.Column('country', sa.String(), nullable=True),
    sa.ForeignKeyConstraint(['owner_id'], ['users.osu_id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tournaments_country'), 'tournaments', ['country'], unique=False)
    op.create_index(op.f('ix_tournaments_max_rank'), 'tournaments', ['max_rank'], unique=False)
    op.create_index(op.f('ix_tournaments_min_rank'), 'tournaments', ['min_rank'], unique=False)
    op.create_table('stage',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('tourn_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['tourn_id'], ['tournaments.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('stage')
    op.drop_index(op.f('ix_tournaments_min_rank'), table_name='tournaments')
    op.drop_index(op.f('ix_tournaments_max_rank'), table_name='tournaments')
    op.drop_index(op.f('ix_tournaments_country'), table_name='tournaments')
    op.drop_table('tournaments')
    op.drop_table('pooled_beatmaps')
    op.drop_table('users')
    op.drop_table('beatmaps')
    # ### end Alembic commands ###