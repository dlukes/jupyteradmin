"""empty message

Revision ID: 257c5951f94f
Revises: None
Create Date: 2016-10-07 14:28:57.306645

"""

# revision identifiers, used by Alembic.
revision = "257c5951f94f"
down_revision = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column("users", sa.Column("group", sa.String(length=256), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("users", "group")
    ### end Alembic commands ###
