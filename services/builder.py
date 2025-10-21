from typing import List
from models.llm import OpenAI_LLM
import os
import logging
from typing import List, Dict
logger = logging.getLogger(__name__)

class PolicyBuilder:
    def __init__(self):
        self.llm = OpenAI_LLM(
            model_name="gpt-4o",  # Changed to match original
            temperature=0.0,
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )

    def create_framework_guided_policy(self, user_description: str, variables_info: List[Dict[str, str]],
                                       framework_name: str) -> str:
        if not user_description.strip():
            return "Error: User description for the policy is required."

        if not variables_info:
            return "Error: No framework variables provided."

        # Format variables as guidance, not content
        guidance_list = "\n".join([f"- {v['variable']}: {v['explanation']}" for v in variables_info])

        prompt = f"""
    You are a policy drafting assistant.

    USER GOAL:
    {user_description}

    FRAMEWORK GUIDE:
    The following framework titled "{framework_name}" provides key dimensions to consider when drafting the policy. These are NOT the content of the policy but should guide structure, scope, or alignment:

    {guidance_list}

    TASK:
    - Draft a policy that achieves the user's intent while addressing relevant framework dimensions where appropriate.
    - Include a title, introduction, 3–6 main sections (can align with or merge framework dimensions), and a conclusion.
    - Each section should tie back to the user goal but reflect awareness of the framework variables.
    - If a dimension is irrelevant to the user's input, skip it.
    """

        try:
            return self.llm(prompt)
        except Exception as e:
            logger.error(f"Error generating framework-guided draft: {e}")
            return f"Error generating draft: {str(e)}"

    def create_policy_draft(self, user_variables: List[str], is_new: bool = True) -> str:
        if not user_variables:
            return "Error: No variables provided for policy creation."

        var_type = "new" if is_new else "existing"
        prompt = f"""
You are a policy creation assistant. The user has provided the following {var_type} variables:
{', '.join(user_variables)}

Please create a cohesive, structured policy draft that includes:
- A policy title and a brief introduction
- Sections corresponding to each variable
- Proposed actions or guidelines
- A conclusion or summary

Cover the essential details.
If any variable is unclear or missing context, note that explicitly.
"""
        try:
            return self.llm(prompt)
        except Exception as e:
            logger.error(f"Error generating policy draft: {e}")
            return f"Error generating policy draft: {str(e)}"