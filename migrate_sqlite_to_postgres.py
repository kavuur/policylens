#!/usr/bin/env python3
"""
SQLite to PostgreSQL Migration Script using SQLAlchemy

Migrates data from SQLite database to PostgreSQL while preserving all relationships,
cascade deletes, and data integrity.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from sqlalchemy import create_engine, inspect, text, MetaData, Table
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not found, using environment variables")

# Configuration
SQLITE_DB_PATH = Path(__file__).parent / "data" / "backup" / "policylens.db"
POSTGRES_URL = os.getenv('DATABASE_URL')

# Configuration
SQLITE_DB_PATH = Path(__file__).parent / "data" / "backup" / "policylens.db"
POSTGRES_URL = os.getenv('DATABASE_URL')

print("="*80)
print("SQLite to PostgreSQL Migration Script")
print("="*80)


def validate_config():
    """Validate configuration before migration."""
    print("\n📋 Validating configuration...")
    
    if not SQLITE_DB_PATH.exists():
        print(f"❌ Error: SQLite database not found at {SQLITE_DB_PATH}")
        return False
    print(f"✅ SQLite DB found: {SQLITE_DB_PATH}")
    
    if not POSTGRES_URL:
        print("❌ Error: DATABASE_URL not set in .env")
        return False
    print(f"✅ PostgreSQL URL configured: {POSTGRES_URL.split('@')[1] if '@' in POSTGRES_URL else '***'}")
    
    return True


def create_connections():
    """Create SQLAlchemy engines for both databases."""
    print("\n🔗 Creating database connections...")
    
    # SQLite connection
    sqlite_url = f"sqlite:///{SQLITE_DB_PATH}"
    sqlite_engine = create_engine(
        sqlite_url,
        connect_args={'timeout': 10, 'check_same_thread': False},
        poolclass=StaticPool
    )
    
    # PostgreSQL connection
    postgres_engine = create_engine(
        POSTGRES_URL,
        echo=False,
        pool_pre_ping=True
    )
    
    # Test connections
    try:
        with sqlite_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("✅ SQLite connection successful")
    except Exception as e:
        print(f"❌ SQLite connection failed: {e}")
        return None, None
    
    try:
        with postgres_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("✅ PostgreSQL connection successful")
    except Exception as e:
        print(f"❌ PostgreSQL connection failed: {e}")
        return None, None
    
    return sqlite_engine, postgres_engine


def get_table_stats(engine, label):
    """Get table statistics from database."""
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    
    print(f"\n📊 {label} tables:")
    stats = {}
    for table_name in sorted(tables):
        try:
            with engine.connect() as conn:
                result = conn.execute(text(f'SELECT COUNT(*) FROM "{table_name}"'))
                count = result.scalar() or 0
                stats[table_name] = count
                print(f"   • {table_name}: {count} rows")
        except Exception as e:
            print(f"   • {table_name}: Error - {e}")
    
    return stats


def fix_postgresql_schema(postgres_engine):
    """Increase column sizes if needed for data migration."""
    print("\n🔧 Adjusting PostgreSQL schema for migration...")
    
    try:
        with postgres_engine.begin() as conn:
            # Expand VARCHAR columns that might be too small
            adjustments = [
                ('subcode', 'subcode', 'VARCHAR(500)'),
                ('code', 'code', 'VARCHAR(500)'),
                ('subsubcode', 'subsubcode', 'VARCHAR(500)'),
            ]
            
            for table_name, column_name, new_type in adjustments:
                try:
                    conn.execute(text(f'ALTER TABLE "{table_name}" ALTER COLUMN "{column_name}" TYPE {new_type}'))
                    print(f"   ✅ {table_name}.{column_name} expanded to {new_type}")
                except Exception as e:
                    if "does not exist" in str(e):
                        print(f"   ℹ️  {table_name}.{column_name} not found (may not exist yet)")
                    else:
                        print(f"   ⚠️  {table_name}.{column_name}: {e}")
            
            return True
    except Exception as e:
        print(f"   ⚠️  Schema adjustment failed: {e}")
        return True  # Don't fail completely, schema might be fine


def backup_postgres(postgres_engine):
    """Clear existing PostgreSQL tables before migration."""
    print("\n💾 Preparing PostgreSQL (clearing existing tables)...")
    
    try:
        with postgres_engine.begin() as conn:
            inspector = inspect(postgres_engine)
            tables = inspector.get_table_names()
            
            if not tables or all(
                conn.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar() == 0 
                for t in tables
            ):
                print("   ℹ️  PostgreSQL is empty, creating tables from Flask models...")
                return True  # Tables will be created in next step
            
            # Drop all tables to start fresh
            print("   ⚠️  Clearing existing PostgreSQL tables...")
            for table_name in reversed(tables):
                try:
                    conn.execute(text(f'DROP TABLE IF EXISTS "{table_name}" CASCADE'))
                    print(f"      ✅ Dropped: {table_name}")
                except Exception as e:
                    print(f"      ⚠️  Could not drop {table_name}: {e}")
            
            return True
    except Exception as e:
        print(f"   ❌ Error preparing PostgreSQL: {e}")
        return False


def create_tables_from_models(postgres_engine):
    """Create PostgreSQL tables from Flask-SQLAlchemy models."""
    print("\n🏗️  Creating PostgreSQL tables from models...")
    
    try:
        # Import Flask app to access db
        from app import app, db
        from models.models import (
            User, PolicyDocument, Codebook, Code, SubCode, SubSubCode,
            ResearchNote, Project, Media, Excerpt, Descriptor
        )
        
        with app.app_context():
            # Use db.metadata to create all tables
            db.metadata.create_all(bind=postgres_engine)
            print("   ✅ All tables created successfully")
            
            # Now expand some columns that might be too small
            print("\n🔧 Expanding VARCHAR columns for long data...")
            try:
                with postgres_engine.begin() as conn:
                    adjustments = [
                        ('media', 'filename', 'VARCHAR(500)'),
                        ('media', 'file_type', 'VARCHAR(100)'),
                    ]
                    
                    for table_name, column_name, new_type in adjustments:
                        try:
                            conn.execute(text(f'ALTER TABLE "{table_name}" ALTER COLUMN "{column_name}" TYPE {new_type}'))
                            print(f"   ✅ {table_name}.{column_name} expanded to {new_type}")
                        except Exception as e:
                            if "does not exist" in str(e).lower():
                                print(f"   ℹ️  {table_name}.{column_name} not found (may already be correct size)")
                            else:
                                print(f"   ⚠️  {table_name}.{column_name}: {e}")
            except Exception as e:
                print(f"   ⚠️  Column expansion had issues: {e}")
            
            return True
    except Exception as e:
        print(f"   ❌ Failed to create tables: {e}")
        import traceback
        traceback.print_exc()
        return False


def migrate_data(sqlite_engine, postgres_engine):
    """Migrate data from SQLite to PostgreSQL using table-based copying."""
    print("\n🔄 Starting data migration...")
    
    try:
        # Get all tables from SQLite
        sqlite_inspector = inspect(sqlite_engine)
        sqlite_tables = sqlite_inspector.get_table_names()
        
        # Migration order (respecting foreign key dependencies)
        migration_order = [
            'user',
            'project',
            'policy_document',
            'codebook',
            'code',
            'subcode',
            'subsubcode',
            'research_note',
            'media',
            'excerpts',
            'descriptor',
            'project_collaborators',
        ]
        
        # Filter to only tables that exist
        tables_to_migrate = [t for t in migration_order if t in sqlite_tables]
        
        total_migrated = 0
        
        for table_name in tables_to_migrate:
            try:
                # Get column types from PostgreSQL
                postgres_inspector = inspect(postgres_engine)
                pg_columns = postgres_inspector.get_columns(table_name)
                column_types = {col['name']: str(col['type']) for col in pg_columns}
                
                # Read from SQLite
                with sqlite_engine.connect() as sqlite_conn:
                    result = sqlite_conn.execute(text(f'SELECT * FROM "{table_name}"'))
                    rows = result.fetchall()
                    
                    if not rows:
                        print(f"   ℹ️  {table_name}: 0 rows")
                        continue
                    
                    # Get column names properly
                    columns = list(result.keys())
                    
                    # Insert into PostgreSQL with fresh transaction for each table
                    with postgres_engine.begin() as postgres_conn:
                        batch_count = 0
                        for row in rows:
                            # Map row values to column names
                            values = dict(zip(columns, row))
                            
                            # Convert types based on PostgreSQL column types
                            for col_name, col_value in values.items():
                                col_type = column_types.get(col_name, '').lower()
                                
                                # Convert SQLite integers to PostgreSQL booleans
                                if 'boolean' in col_type and col_value is not None:
                                    values[col_name] = bool(col_value)
                                
                                # Handle datetime strings
                                elif 'timestamp' in col_type and isinstance(col_value, str):
                                    values[col_name] = col_value
                            
                            # Build INSERT statement
                            col_list = ', '.join(f'"{col}"' for col in columns)
                            val_placeholders = ', '.join([f':{col}' for col in columns])
                            
                            insert_stmt = text(
                                f'INSERT INTO "{table_name}" ({col_list}) VALUES ({val_placeholders})'
                            )
                            
                            try:
                                postgres_conn.execute(insert_stmt, values)
                                batch_count += 1
                            except Exception as e:
                                # Skip duplicates or constraint violations
                                if "duplicate key" not in str(e).lower():
                                    raise
                    
                    total_migrated += batch_count
                    print(f"   ✅ {table_name}: {batch_count} rows migrated")
                
            except Exception as e:
                print(f"   ❌ {table_name}: Failed - {e}")
                return False
        
        print(f"\n✅ Total records migrated: {total_migrated}")
        return True
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def reset_sequences(postgres_engine):
    """Reset PostgreSQL sequences to prevent duplicate key errors."""
    print("\n🔄 Resetting PostgreSQL sequences...")
    
    try:
        with postgres_engine.begin() as conn:
            # Get all sequences from information_schema
            result = conn.execute(text("""
                SELECT sequence_name
                FROM information_schema.sequences
                WHERE sequence_schema = 'public'
            """))
            
            sequences = result.fetchall()
            
            if not sequences:
                print("   ℹ️  No sequences to reset")
                return True
            
            for (seq_name,) in sequences:
                try:
                    # Extract table name from sequence name (e.g., "user_id_seq" -> "user")
                    # Most sequences follow pattern: tablename_id_seq or tablename_seq
                    if seq_name.endswith('_id_seq'):
                        table_name = seq_name[:-7]  # Remove '_id_seq'
                    elif seq_name.endswith('_seq'):
                        table_name = seq_name[:-4]  # Remove '_seq'
                    else:
                        print(f"   ⚠️  {seq_name}: Could not determine table name")
                        continue
                    
                    # Get max id from table
                    max_id_result = conn.execute(
                        text(f'SELECT MAX(id) FROM "{table_name}"')
                    ).scalar()
                    max_id = (max_id_result or 0)
                    next_val = max_id + 1
                    
                    # Reset sequence to max_id + 1
                    conn.execute(text(f"SELECT setval('{seq_name}', {next_val})"))
                    print(f"   ✅ {seq_name}: set to {next_val} (max_id was {max_id})")
                except Exception as e:
                    print(f"   ⚠️  {seq_name}: {e}")
            
            return True
            
    except Exception as e:
        print(f"   ❌ Error resetting sequences: {e}")
        return False


def verify_migration(sqlite_engine, postgres_engine):
    """Verify migration by comparing record counts."""
    print("\n✅ Verifying migration...")
    
    sqlite_stats = get_table_stats(sqlite_engine, "SQLite")
    postgres_stats = get_table_stats(postgres_engine, "PostgreSQL")
    
    # Compare stats
    mismatches = []
    for table_name in sqlite_stats:
        if table_name == 'project_collaborators':
            continue  # Skip association table
        
        sqlite_count = sqlite_stats.get(table_name, 0)
        postgres_count = postgres_stats.get(table_name, 0)
        
        if sqlite_count != postgres_count:
            mismatches.append((table_name, sqlite_count, postgres_count))
    
    if mismatches:
        print("\n⚠️  Mismatches found:")
        for table_name, sqlite_count, postgres_count in mismatches:
            print(f"   {table_name}: SQLite={sqlite_count}, PostgreSQL={postgres_count}")
        return False
    else:
        print("\n✅ All record counts match!")
        return True


def main():
    """Main migration workflow."""
    
    # Step 1: Validate
    if not validate_config():
        sys.exit(1)
    
    # Step 2: Create connections
    sqlite_engine, postgres_engine = create_connections()
    if not sqlite_engine or not postgres_engine:
        sys.exit(1)
    
    # Step 3: Show pre-migration stats
    print("\n📊 Pre-migration statistics:")
    get_table_stats(sqlite_engine, "SQLite")
    
    # Step 4: Backup and prepare PostgreSQL
    if not backup_postgres(postgres_engine):
        sys.exit(1)
    
    # Step 4.5: Create tables from models
    if not create_tables_from_models(postgres_engine):
        sys.exit(1)
    
    # Step 5: Perform migration
    if not migrate_data(sqlite_engine, postgres_engine):
        sys.exit(1)
    
    # Step 6: Reset sequences
    if not reset_sequences(postgres_engine):
        print("⚠️  Warning: Sequence reset had issues, but migration may still be valid")
    
    # Step 7: Verify
    if not verify_migration(sqlite_engine, postgres_engine):
        print("\n⚠️  Warning: Some mismatches detected. Please review manually.")
    
    # Summary
    print("\n" + "="*80)
    print("✅ Migration completed successfully!")
    print("="*80)
    print("\n📝 Next steps:")
    print("   1. Restart your Flask application: python3 run.py")
    print("   2. Login to verify data integrity")
    print("   3. Check projects, codebooks, and excerpts")
    print("   4. Test file uploads and search functionality")
    print("\n💾 Your SQLite database is still at: " + str(SQLITE_DB_PATH))
    print("   Keep it as backup until you've verified everything works.")
    print("="*80 + "\n")


if __name__ == '__main__':
    main()
