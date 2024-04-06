"""initial migration

Revision ID: 1dddbd9c8ae6
Revises: 
Create Date: 2023-08-05 16:54:49.302729

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1dddbd9c8ae6'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('Expenses', schema=None) as batch_op:
        batch_op.alter_column('date',
               existing_type=sa.TEXT(),
               type_=sa.String(length=64),
               existing_nullable=True)
        batch_op.alter_column('category',
               existing_type=sa.TEXT(),
               type_=sa.String(length=64),
               existing_nullable=True)
        batch_op.alter_column('description',
               existing_type=sa.TEXT(),
               type_=sa.String(length=64),
               existing_nullable=True)
        batch_op.alter_column('amount',
               existing_type=sa.INTEGER(),
               type_=sa.Float(),
               existing_nullable=True)

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('expense_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(None, 'Expenses', ['expense_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('expense_id')

    with op.batch_alter_table('Expenses', schema=None) as batch_op:
        batch_op.alter_column('amount',
               existing_type=sa.Float(),
               type_=sa.INTEGER(),
               existing_nullable=True)
        batch_op.alter_column('description',
               existing_type=sa.String(length=64),
               type_=sa.TEXT(),
               existing_nullable=True)
        batch_op.alter_column('category',
               existing_type=sa.String(length=64),
               type_=sa.TEXT(),
               existing_nullable=True)
        batch_op.alter_column('date',
               existing_type=sa.String(length=64),
               type_=sa.TEXT(),
               existing_nullable=True)

    # ### end Alembic commands ###