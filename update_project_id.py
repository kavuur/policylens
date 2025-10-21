from app import app, db
from models import Excerpt

def update_project_id(old_id, new_id):
    with app.app_context():
        try:
            # Update the project_id in the excerpts table
            updated = Excerpt.query.filter_by(project_id=old_id).update({'project_id': new_id})
            db.session.commit()
            print(f"Successfully updated {updated} excerpts from project_id {old_id} to {new_id}")
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Error updating project_id: {str(e)}")
            return False

if __name__ == '__main__':
    update_project_id(1, 2)
