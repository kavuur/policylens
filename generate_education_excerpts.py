from app import app, db
from models import Excerpt, Media, Codebook, User, Project
from datetime import datetime, timedelta
import random

# Dummy data for education policy excerpts
dummy_excerpts = [
    {
        "excerpt": "The implementation of STEM education programs in primary schools has shown a 25% increase in student engagement with science subjects. Teachers reported that hands-on activities and project-based learning approaches were particularly effective in maintaining student interest. However, challenges remain in providing adequate training for educators to deliver these programs effectively. Schools with dedicated STEM labs and resources showed better outcomes compared to those without. This suggests that infrastructure investment is a critical factor in STEM education success.",
        "code": "STEM",
        "subcode": "Engagement",
        "explanation": "This excerpt highlights the positive impact of STEM education programs on student engagement. The 25% increase in engagement is significant and suggests that hands-on, project-based approaches are effective. The mention of training challenges for educators indicates a potential area for professional development. The correlation between infrastructure and outcomes underscores the need for adequate resources in STEM education. These findings could inform policy decisions about resource allocation in education."
    },
    {
        "excerpt": "A recent study on early childhood education reveals that children who attend quality preschool programs are 40% more likely to graduate from high school. The research followed students from low-income families over a 15-year period. Key factors contributing to this success include small class sizes, well-trained teachers, and a curriculum focused on social-emotional development. The study also found that these benefits were most pronounced for children from disadvantaged backgrounds. This evidence supports the expansion of early childhood education initiatives.",
        "code": "ECE",
        "subcode": "LongTermOutcomes",
        "explanation": "This finding is crucial for education policy as it demonstrates the long-term benefits of early childhood education, particularly for disadvantaged students. The 40% increase in high school graduation rates is substantial and suggests that early interventions can have lasting impacts. The identified success factors (small classes, trained teachers, social-emotional focus) provide clear guidance for program design. The emphasis on disadvantaged populations highlights the potential for such programs to address educational inequality. This research could be used to advocate for increased funding and expansion of early childhood education programs."
    },
    {
        "excerpt": "The integration of technology in classrooms has shown mixed results, with some studies indicating improved learning outcomes while others show no significant effect. A meta-analysis of 50 studies found that technology is most effective when used as a supplement to traditional teaching methods rather than a replacement. Teachers reported that professional development on technology integration was the strongest predictor of successful implementation. Students in schools with 1:1 device programs showed improved digital literacy but no significant gains in core subjects. This suggests that technology should be carefully integrated with clear educational objectives.",
        "code": "TECH",
        "subcode": "Integration",
        "explanation": "This excerpt presents a nuanced view of technology in education, which is important for making informed policy decisions. The mixed findings suggest that simply providing technology is not enough; how it's implemented matters. The emphasis on professional development aligns with other research showing that teacher training is crucial for successful technology integration. The finding about digital literacy versus core subject performance suggests that technology may have different impacts on different learning outcomes. This could inform more targeted approaches to technology use in education."
    },
    {
        "excerpt": "Research on school funding equity reveals that districts serving predominantly low-income students receive significantly less funding than wealthier districts in most states. This funding gap has been linked to disparities in educational outcomes, including test scores and college attendance rates. States that have implemented weighted student funding formulas have seen reductions in these achievement gaps. However, political and logistical challenges often prevent comprehensive reform. The findings highlight the need for more equitable school funding policies to ensure all students have access to quality education.",
        "code": "FUNDING",
        "subcode": "Equity",
        "explanation": "This excerpt addresses a critical issue in education policy: the relationship between funding and educational equity. The documented funding gap between wealthy and poor districts is concerning given its impact on student outcomes. The success of weighted funding formulas in reducing achievement gaps is an important finding that could guide policy decisions. The mention of political challenges provides context for why these issues persist despite evidence of solutions. This research could be used to advocate for more equitable funding models in education."
    },
    {
        "excerpt": "A longitudinal study on teacher retention found that new teachers who received comprehensive mentoring were 30% more likely to remain in the profession after five years. The most effective mentoring programs included regular classroom observations, collaborative planning time, and emotional support. Teachers in high-needs schools particularly benefited from these programs, with retention rates increasing by up to 45%. The study suggests that investing in teacher support can help address teacher shortages and improve educational quality. These findings have important implications for teacher preparation and professional development policies.",
        "code": "STAFFING",
        "subcode": "Retention",
        "explanation": "This research provides valuable insights into addressing teacher retention, a critical issue in education. The 30% increase in retention for mentored teachers is substantial and suggests that support systems can make a significant difference. The specific components of effective mentoring programs (observations, planning time, emotional support) offer practical guidance for program design. The even greater impact in high-needs schools is particularly noteworthy, as these schools often face the greatest staffing challenges. These findings could inform policies related to teacher induction and support programs."
    }
]

def create_dummy_excerpts():
    with app.app_context():
        # Get project with ID 5
        project = Project.query.get(5)
        if not project:
            print("Error: Project with ID 5 not found")
            return
        
        # Get a media item from the project
        media = Media.query.filter_by(project_id=5).first()
        if not media:
            print("Error: No media found in project 5")
            return
        
        # Get a codebook from the project
        codebook = Codebook.query.filter_by(project_id=5).first()
        if not codebook:
            print("Error: No codebook found in project 5")
            return
        
        # Get a user (admin)
        user = User.query.first()
        if not user:
            print("Error: No users found in the database")
            return
        
        # Create dummy excerpts
        for i, data in enumerate(dummy_excerpts):
            excerpt = Excerpt(
                project_id=5,
                media_id=media.id,
                codebook_id=codebook.id,
                code=data['code'],
                subcode=data['subcode'],
                excerpt=data['excerpt'],
                explanation=data['explanation'],
                user_id=user.id,
                created_at=datetime.utcnow() - timedelta(days=len(dummy_excerpts)-i)  # Stagger creation dates
            )
            db.session.add(excerpt)
        
        try:
            db.session.commit()
            print(f"Successfully created {len(dummy_excerpts)} dummy excerpts for project 5")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating dummy excerpts: {str(e)}")

if __name__ == "__main__":
    create_dummy_excerpts()
