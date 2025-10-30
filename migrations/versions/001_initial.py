"""Initial migration

Revision ID: 001
Create Date: 2025-10-30
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

def upgrade():
    # Create domain_reports table
    op.create_table('domain_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('reputation', sa.Integer(), nullable=True),
        sa.Column('harmless', sa.Integer(), nullable=True),
        sa.Column('malicious', sa.Integer(), nullable=True),
        sa.Column('suspicious', sa.Integer(), nullable=True),
        sa.Column('undetected', sa.Integer(), nullable=True),
        sa.Column('categories', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('last_analysis_date', sa.DateTime(), nullable=True),
        sa.Column('raw_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_domain_reports_domain'), 'domain_reports', ['domain'], unique=True)

    # Create ip_reports table
    op.create_table('ip_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('reputation', sa.Integer(), nullable=True),
        sa.Column('harmless', sa.Integer(), nullable=True),
        sa.Column('malicious', sa.Integer(), nullable=True),
        sa.Column('suspicious', sa.Integer(), nullable=True),
        sa.Column('undetected', sa.Integer(), nullable=True),
        sa.Column('country', sa.String(length=2), nullable=True),
        sa.Column('asn', sa.Integer(), nullable=True),
        sa.Column('as_owner', sa.String(length=255), nullable=True),
        sa.Column('raw_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ip_reports_ip_address'), 'ip_reports', ['ip_address'], unique=True)

    # Create file_reports table
    op.create_table('file_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('file_hash', sa.String(length=64), nullable=False),
        sa.Column('hash_type', sa.String(length=10), nullable=True),
        sa.Column('meaningful_name', sa.String(length=255), nullable=True),
        sa.Column('size', sa.Integer(), nullable=True),
        sa.Column('type_description', sa.String(length=255), nullable=True),
        sa.Column('harmless', sa.Integer(), nullable=True),
        sa.Column('malicious', sa.Integer(), nullable=True),
        sa.Column('suspicious', sa.Integer(), nullable=True),
        sa.Column('undetected', sa.Integer(), nullable=True),
        sa.Column('raw_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_file_reports_file_hash'), 'file_reports', ['file_hash'], unique=True)

    # Create api_rate_limits table
    op.create_table('api_rate_limits',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('minute_timestamp', sa.DateTime(), nullable=False),
        sa.Column('request_count', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_api_rate_limits_minute_timestamp'), 'api_rate_limits', ['minute_timestamp'], unique=False)

def downgrade():
    op.drop_table('api_rate_limits')
    op.drop_table('file_reports')
    op.drop_table('ip_reports')
    op.drop_table('domain_reports')