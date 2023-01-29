"""Fifth Update.

Revision ID: 98c3d8971d70
Revises: 98c3d8971d6f
Create Date: 2020-04-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '98c3d8971d70'
down_revision = '98c3d8971d6f'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('deployments', sa.Column('template_parameters', sa.Text, nullable=True))
    op.add_column('deployments', sa.Column('template_metadata', sa.Text, nullable=True))
    # ### end Alembic commands ###


def downgrade():
    op.drop_column('deployments', 'template_parameters')
    op.drop_column('deployments', 'template_metadata')
    # ### end Alembic commands ###
