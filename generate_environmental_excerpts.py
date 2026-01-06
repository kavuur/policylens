from app import app, db
from models import Excerpt, Media, Codebook, User, Project
from datetime import datetime, timedelta
import random

# Dummy data for environmental policy excerpts
environmental_excerpts = [
    {
        "excerpt": "The Carbon Pricing Leadership Coalition reports that carbon pricing, when effectively implemented, can reduce emissions by up to 24% by 2025. Our analysis of the European Union Emissions Trading System (EU ETS) shows a 21% reduction in emissions from regulated sectors since its inception. The success of carbon pricing largely depends on setting an appropriate price point that reflects the true social cost of carbon while remaining economically viable for industries to transition.",
        "code": "CLIMATE",
        "subcode": "Carbon Pricing",
        "explanation": "This excerpt highlights the effectiveness of carbon pricing mechanisms in reducing greenhouse gas emissions. The 24% reduction potential by 2025 demonstrates significant impact, while the EU ETS case study provides real-world validation. The mention of balancing economic viability with environmental goals is crucial for policy design. This data could be used to advocate for expanded carbon pricing initiatives in other regions or sectors."
    },
    {
        "excerpt": "The Circular Economy Action Plan estimates that adopting circular economy principles could generate €1.8 trillion in economic benefits for Europe by 2030. Our research on extended producer responsibility (EPR) schemes shows a 42% increase in recycling rates for packaging materials in countries with mandatory EPR legislation. The key success factors include clear design standards, financial incentives for recyclability, and robust collection infrastructure.",
        "code": "WASTE",
        "subcode": "Circular Economy",
        "explanation": "This excerpt presents compelling economic and environmental arguments for circular economy policies. The €1.8 trillion figure provides a strong economic case, while the 42% recycling rate increase demonstrates practical impact. The identification of success factors offers actionable insights for policymakers. This evidence could support the expansion of EPR schemes to additional product categories or regions."
    },
    {
        "excerpt": "The Global Biodiversity Framework sets a target of protecting 30% of land and sea areas by 2030. Our analysis of protected area management effectiveness shows that well-funded, community-involved conservation areas have 3-4 times higher biodiversity indicators than those without these characteristics. The most successful programs integrate traditional ecological knowledge with modern conservation science.",
        "code": "BIODIVERSITY",
        "subcode": "Protected Areas",
        "explanation": "This excerpt connects global biodiversity targets with local implementation strategies. The 30x30 target provides a clear benchmark, while the 3-4x effectiveness metric highlights the importance of proper resourcing and community engagement. The emphasis on integrating traditional knowledge with scientific approaches offers a model for inclusive conservation. These findings could inform the design of new protected areas or the improvement of existing ones."
    },
    {
        "excerpt": "The transition to renewable energy requires an estimated $4.4 trillion annual investment through 2030 to meet Paris Agreement goals. Our case study of Germany's Energiewende shows that feed-in tariffs can accelerate renewable adoption, with solar capacity increasing from 6 GW in 2006 to 58 GW in 2021. However, the policy must be carefully designed to balance growth with grid stability and affordability.",
        "code": "ENERGY",
        "subcode": "Renewables",
        "explanation": "This excerpt provides critical context about the financial scale of the energy transition while offering a successful policy example. The $4.4 trillion figure underscores the magnitude of investment needed, while the German case study demonstrates what's achievable with the right policies. The caution about policy design highlights the need for balanced approaches that consider multiple objectives. This analysis could help shape renewable energy policies in other jurisdictions."
    },
    {
        "excerpt": "Urban green infrastructure can reduce heat island effects by up to 5°C and manage 30% of stormwater runoff. Our analysis of Singapore's ABC Waters program shows a 40% increase in biodiversity and 25% reduction in energy costs for cooling in buildings near green spaces. The most effective projects combine ecological benefits with recreational and cultural values to gain public support.",
        "code": "URBAN",
        "subcode": "Green Infrastructure",
        "explanation": "This excerpt demonstrates the multiple benefits of urban green infrastructure, from temperature regulation to biodiversity and energy savings. The Singapore case study provides concrete evidence of these benefits, with the 5°C reduction in heat island effect being particularly significant for climate adaptation. The emphasis on multifunctional design that serves both ecological and social purposes is a key insight for urban planners. These findings could be used to advocate for increased investment in urban green spaces."
    }
]

def create_environmental_excerpts():
    with app.app_context():
        # Get the project with ID 5
        project = Project.query.get(5)
        if not project:
            print("Error: Project with ID 5 not found")
            return
        
        # Get media with ID 10
        media = Media.query.get(10)
        if not media:
            print("Error: Media with ID 10 not found")
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
        
        # Create environmental excerpts
        for i, data in enumerate(environmental_excerpts):
            excerpt = Excerpt(
                project_id=5,
                media_id=10,  # Using the specified media ID
                codebook_id=codebook.id,
                code=data['code'],
                subcode=data['subcode'],
                excerpt=data['excerpt'],
                explanation=data['explanation'],
                user_id=user.id,
                created_at=datetime.utcnow() - timedelta(days=len(environmental_excerpts)-i)  # Stagger creation dates
            )
            db.session.add(excerpt)
        
        try:
            db.session.commit()
            print(f"Successfully created {len(environmental_excerpts)} environmental policy excerpts for project 5 and media 10")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating environmental excerpts: {str(e)}")

if __name__ == "__main__":
    create_environmental_excerpts()
