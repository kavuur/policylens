from app import app, db

with app.app_context():
    # Create all database tables
    db.create_all()
    
    # Get table information
    inspector = db.inspect(db.engine)
    tables = inspector.get_table_names()
    
    print("\n=== Database Tables ===")
    for table_name in tables:
        print(f"\nTable: {table_name}")
        print("Columns:")
        for column in inspector.get_columns(table_name):
            print(f"  {column['name']}: {column['type']}")
        
        print("\n  Foreign Keys:")
        for fk in inspector.get_foreign_keys(table_name):
            print(f"  - {fk['constrained_columns']} references {fk['referred_table']}.{fk['referred_columns']}")
        
        print("\n  Indexes:")
        for index in inspector.get_indexes(table_name):
            print(f"  - {index['name']}: {index['column_names']}")
    
    print("\n=== Database Schema Check Complete ===")
