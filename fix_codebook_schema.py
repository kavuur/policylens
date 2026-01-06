from app import app, db

def upgrade():
    with app.app_context():
        # Add project_id column to codebook table if it doesn't exist
        db.engine.execute('''
            PRAGMA foreign_keys=off;
            BEGIN TRANSACTION;
            
            -- Create a new table with the correct schema
            CREATE TABLE codebook_new (
                id INTEGER NOT NULL, 
                name VARCHAR(200) NOT NULL, 
                description TEXT, 
                created_at DATETIME, 
                updated_at DATETIME, 
                user_id INTEGER NOT NULL, 
                project_id INTEGER, 
                PRIMARY KEY (id), 
                FOREIGN KEY(user_id) REFERENCES user (id), 
                FOREIGN KEY(project_id) REFERENCES project (id)
            );
            
            -- Copy data from old table to new table
            INSERT INTO codebook_new (id, name, description, created_at, updated_at, user_id)
            SELECT id, name, description, created_at, updated_at, user_id FROM codebook;
            
            -- Drop old table and rename new one
            DROP TABLE codebook;
            ALTER TABLE codebook_new RENAME TO codebook;
            
            -- Recreate indexes
            CREATE INDEX ix_codebook_user_id ON codebook (user_id);
            CREATE INDEX ix_codebook_project_id ON codebook (project_id);
            
            COMMIT;
            PRAGMA foreign_keys=on;
        ''')
        print("Database schema updated successfully!")

if __name__ == '__main__':
    upgrade()
