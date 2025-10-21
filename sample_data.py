import os
import sys
from datetime import datetime, timedelta
from faker import Faker
from werkzeug.security import generate_password_hash

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User, Project, Codebook, Code, SubCode, SubSubCode, Media, Descriptor, ResearchNote, PolicyDocument

def create_sample_data():
    """Create sample data for the database."""
    print("Creating sample data...")
    fake = Faker()
    
    # Clear existing data
    print("Clearing existing data...")
    db.drop_all()
    db.create_all()
    
    # Create users
    print("Creating users...")
    users = []
    for i in range(3):
        user = User(
            username=f'user{i+1}',
            email=f'user{i+1}@example.com',
            name=fake.name(),
            is_active=True,
            age_group=fake.random_element(('18-25', '26-35', '36-45', '46-55', '56+')),
            sex=fake.random_element(('Male', 'Female', 'Other')),
            industry=fake.job(),
            organization=fake.company()
        )
        user.set_password('password123')
        users.append(user)
        db.session.add(user)
    
    db.session.commit()
    
    # Create projects
    print("Creating projects...")
    projects = []
    for i in range(5):
        project = Project(
            name=f"{fake.catch_phrase()} Project",
            description=fake.paragraph(),
            owner_id=users[i % len(users)].id,
            created_at=datetime.utcnow() - timedelta(days=fake.random_int(1, 30)),
            excerpts_count=fake.random_int(0, 50)
        )
        projects.append(project)
        db.session.add(project)
    
    db.session.commit()
    
    # Create codebooks
    print("Creating codebooks...")
    codebooks = []
    codebook_names = ["Education Policy", "Healthcare Analysis", "Technology Trends", "Environmental Studies", "Social Research"]
    
    for i, name in enumerate(codebook_names):
        codebook = Codebook(
            name=name,
            description=f"Codebook for {name} research",
            user_id=users[i % len(users)].id,
            project_id=projects[i % len(projects)].id if i < len(projects) else None,
            created_at=datetime.utcnow() - timedelta(days=fake.random_int(1, 60))
        )
        codebooks.append(codebook)
        db.session.add(codebook)
    
    db.session.commit()
    
    # Create codes, subcodes, and subsubcodes
    print("Creating codes and subcodes...")
    for codebook in codebooks:
        # Create 3-5 main codes per codebook
        for _ in range(fake.random_int(3, 5)):
            code = Code(
                code=fake.unique.bothify(text='C##'),
                description=fake.sentence(),
                codebook_id=codebook.id,
                created_at=datetime.utcnow() - timedelta(days=fake.random_int(1, 30))
            )
            db.session.add(code)
            db.session.flush()  # Get the code ID
            
            # Create 2-4 subcodes per code
            for _ in range(fake.random_int(2, 4)):
                subcode = SubCode(
                    subcode=fake.unique.bothify(text='SC##'),
                    description=fake.sentence(),
                    code_id=code.id,
                    created_at=datetime.utcnow() - timedelta(days=fake.random_int(1, 15))
                )
                db.session.add(subcode)
                db.session.flush()
                
                # Create 0-3 subsubcodes per subcode
                for _ in range(fake.random_int(0, 3)):
                    subsubcode = SubSubCode(
                        subsubcode=fake.unique.bothify(text='SSC##'),
                        description=fake.sentence(),
                        subcode_id=subcode.id,
                        created_at=datetime.utcnow() - timedelta(days=fake.random_int(1, 7))
                    )
                    db.session.add(subsubcode)
            
            fake.unique.clear()  # Reset unique values for next iteration
    
    db.session.commit()
    
    # Create media items
    print("Creating media items...")
    media_categories = ['education', 'health', 'ict', 'government', 'security', 'other']
    media_types = ['brief', 'publication', 'law', 'policy', 'other']
    
    for i in range(10):
        media = Media(
            filename=f"document_{i+1}.pdf",
            description=f"Sample {fake.word().capitalize()} Document",
            category=fake.random_element(media_categories),
            type=fake.random_element(media_types),
            visibility=fake.random_element(('private', 'public')),
            file_type='application/pdf',
            file_size=fake.random_int(100000, 5000000),  # 100KB to 5MB
            user_id=users[i % len(users)].id,
            project_id=projects[i % len(projects)].id if i < len(projects) else None,
            uploaded_at=datetime.utcnow() - timedelta(days=fake.random_int(1, 60))
        )
        db.session.add(media)
        db.session.flush()
        
        # Add 2-5 descriptors per media item
        for _ in range(fake.random_int(2, 5)):
            descriptor = Descriptor(
                key=fake.word(),
                value=fake.sentence(),
                media_id=media.id
            )
            db.session.add(descriptor)
    
    db.session.commit()
    
    # Create research notes
    print("Creating research notes...")
    for i in range(8):
        note = ResearchNote(
            title=f"Research Note: {fake.sentence(4)}",
            content='\n\n'.join(fake.paragraphs(nb=3, ext_word_list=None)),
            created_at=datetime.utcnow() - timedelta(days=fake.random_int(1, 45)),
            user_id=users[i % len(users)].id
        )
        db.session.add(note)
    
    db.session.commit()
    
    # Create policy documents
    print("Creating policy documents...")
    for i in range(6):
        doc = PolicyDocument(
            title=f"Policy Document: {fake.sentence(3)}",
            content=fake.text(max_nb_chars=2000),
            category=fake.random_element(('Education', 'Health', 'Technology', 'Environment', 'Economy')),
            created_at=datetime.utcnow() - timedelta(days=fake.random_int(1, 90)),
            updated_at=datetime.utcnow() - timedelta(days=fake.random_int(0, 30)),
            user_id=users[i % len(users)].id
        )
        db.session.add(doc)
    
    db.session.commit()
    
    print("Sample data created successfully!")

if __name__ == '__main__':
    with app.app_context():
        create_sample_data()
