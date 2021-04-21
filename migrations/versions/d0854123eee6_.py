"""empty message

Revision ID: d0854123eee6
Revises: 03ba63986a38
Create Date: 2021-04-20 23:45:15.799586

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd0854123eee6'
down_revision = '03ba63986a38'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('access_token', sa.String(), nullable=True))
    op.add_column('users', sa.Column('refresh_token', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'refresh_token')
    op.drop_column('users', 'access_token')
    # ### end Alembic commands ###