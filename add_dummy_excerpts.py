from app import app, db
from models import Project, Media, Excerpt, User
from datetime import datetime, timedelta
import random

def create_dummy_excerpts():
    with app.app_context():
        # Get the first project, media, and user
        project = Project.query.first()
        if not project:
            print("No projects found. Please create a project first.")
            return
            
        media_items = Media.query.filter_by(project_id=project.id).all()
        if not media_items:
            print("No media items found in the project. Please add some media first.")
            return
            
        user = User.query.first()
        if not user:
            print("No users found. Please create a user first.")
            return
        
        # Sample data for excerpts
        sample_codes = ['THEME1', 'THEME2', 'THEME3', 'THEME4', 'THEME5']
        sample_subcodes = ['SUB1', 'SUB2', 'SUB3', 'SUB4', 'SUB5', '']
        
        sample_excerpts = [
            "The study found significant improvements in student performance.",
            "Participants reported higher satisfaction levels with the new system.",
            "The data suggests a strong correlation between the two variables.",
            "Further research is needed to confirm these preliminary findings.",
            "The results were consistent across all demographic groups.",
            "This finding aligns with previous research in the field.",
            "The intervention had a statistically significant effect.",
            "Limitations of the study include the small sample size.",
            "Future studies should investigate this relationship further.",
            "The implications of these findings are discussed below."
        ]
        
        sample_explanations = [
            "This finding is particularly interesting because...",
            "This suggests that our hypothesis was correct.",
            "This aligns with the work of Smith et al. (2020).",
            "Further investigation is needed to understand why this occurred.",
            "This has important implications for policy makers.",
            "The data quality in this area was particularly strong.",
            "This was an unexpected but interesting finding.",
            "This supports the theoretical framework we proposed.",
            "The practical applications of this are significant.",
            "This finding warrants further investigation."
        ]
        
        # Create 10 dummy excerpts
        for i in range(10):
            excerpt = Excerpt(
                project_id=project.id,
                media_id=random.choice(media_items).id,
                code=random.choice(sample_codes),
                subcode=random.choice(sample_subcodes) if random.random() > 0.3 else None,
                excerpt=random.choice(sample_excerpts),
                explanation=random.choice(sample_explanations) if random.random() > 0.2 else None,
                user_id=user.id,
                created_at=datetime.utcnow() - timedelta(days=random.randint(0, 30))
            )
            db.session.add(excerpt)
        
        try:
            db.session.commit()
            print(f"Successfully added 10 dummy excerpts to project: {project.name}")
        except Exception as e:
            db.session.rollback()
            print(f"Error adding dummy excerpts: {str(e)}")

if __name__ == '__main__':
    create_dummy_excerpts()
