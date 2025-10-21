import sys
import os
from datetime import datetime, timedelta
from faker import Faker

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User, Project, Media, Codebook, Excerpt

def create_sample_excerpts():
    print("Creating sample excerpts...")
    fake = Faker()
    
    with app.app_context():
        # Get some sample data
        users = User.query.limit(3).all()
        projects = Project.query.limit(2).all()
        
        if not users or not projects:
            print("Need to have at least one user and one project. Run sample_data.py first.")
            return
            
        for i in range(20):  # Create 20 sample excerpts
            project = projects[i % len(projects)]
            user = users[i % len(users)]
            
            # Get media items from this project
            media_items = Media.query.filter_by(project_id=project.id).all()
            if not media_items:
                print(f"No media items found for project {project.id}, skipping...")
                continue
                
            media = media_items[i % len(media_items)]
            
            # Get codebooks for this project
            codebooks = Codebook.query.filter_by(project_id=project.id).all()
            codebook = codebooks[0] if codebooks else None
            
            # Create the excerpt
            excerpt = Excerpt(
                project_id=project.id,
                media_id=media.id,
                codebook_id=codebook.id if codebook else None,
                code=f"CODE-{i%5+1}",
                subcode=f"SUB-{i%3+1}" if i % 2 == 0 else None,
                excerpt=fake.paragraph(nb_sentences=3),
                explanation=fake.paragraph(nb_sentences=2) if i % 3 != 0 else None,
                created_at=datetime.utcnow() - timedelta(days=i),
                user_id=user.id
            )
            
            db.session.add(excerpt)
        
        db.session.commit()
        print("Sample excerpts created successfully!")

if __name__ == "__main__":
    create_sample_excerpts()
