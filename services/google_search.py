import os
import requests
from urllib.parse import urlparse
import hashlib
from typing import List, Dict
from datetime import datetime
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
# Load environment variables from .env file
load_dotenv()

class GoogleSearchService:
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        self.search_engine_id = os.getenv("GOOGLE_CSE_ID")
        self.allowed_topics = [
            "mental health", "diabetes", "stroke", "heart disease",
            "hypertension", "cancer", "non-communicable diseases",
            "Healthcare", "Health Care", "NCDs", "CMDs", "CVDs", "policy related"
        ]

        if not self.api_key or not self.search_engine_id:
            raise EnvironmentError("GOOGLE_API_KEY or GOOGLE_CSE_ID is not set. Please check your .env file.")

    def validate_topic(self, query: str) -> bool:
        """Check if query contains any of the allowed topics.
        If allowed_topics is empty, allow all queries."""
        if not self.allowed_topics:  # empty list means relax the gate
            return True
        query_lower = query.lower()
        return any(topic.lower() in query_lower for topic in self.allowed_topics)

    def search_google(self, query: str, num_results: int = 10) -> List[Dict]:
        """Search Google for PDF documents related to the query"""
        if not self.validate_topic(query):
            raise ValueError(
                f"Search query must contain one of the allowed topics: {', '.join(self.allowed_topics)}"
            )

        base_url = "https://www.googleapis.com/customsearch/v1"
        params = {
            'q': query + " filetype:pdf",
            'key': self.api_key,
            'cx': self.search_engine_id,
            'num': num_results,
            'fileType': 'pdf'
        }

        try:
            response = requests.get(base_url, params=params)
            response.raise_for_status()
            results = response.json()
            return self._format_results(results.get('items', []))
        except Exception as e:
            logger.error(f"Error during Google search: {e}")
            raise

    def _format_results(self, items: List[Dict]) -> List[Dict]:
        """Format Google search results for display"""
        formatted = []
        for item in items:
            formatted.append({
                'title': item.get('title', 'No title'),
                'url': item.get('link'),
                'source': self._get_domain(item.get('link')),
                'snippet': item.get('snippet', 'No description available'),
                'retrieved_at': str(datetime.now())
            })
        return formatted

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc
