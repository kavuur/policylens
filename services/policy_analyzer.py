# services/policy_analyzer.py
import os
import logging
from typing import List, Dict
from models.llm import OpenAI_LLM
from .google_search import GoogleSearchService  # Assuming this is importable; adjust path if needed
from .builder import PolicyBuilder  # Reuse existing PolicyBuilder
import requests

logger = logging.getLogger(__name__)


class PolicyAnalyzer:
    def __init__(self):
        self.llm = OpenAI_LLM(model_name="gpt-4o", temperature=0.0, openai_api_key=os.getenv("OPENAI_API_KEY"))
        self.policy_builder = PolicyBuilder()  # Reuse for suggestion generation
        self.google_search = GoogleSearchService()

    def derive_keywords(self, policy_text: str) -> List[str]:
        """Use LLM to derive 3-5 keywords from policy text for evidence search."""
        prompt = f"""
        You are a policy analyst. Given this policy document excerpt, derive 3-5 concise keywords or phrases 
        that capture core themes (e.g., 'mental health funding', 'diabetes prevention') for searching evidence.

        Policy Text: {policy_text[:5000]}  # Truncate for token limits

        Output ONLY a comma-separated list of keywords, e.g., keyword1, keyword2, keyword3.
        """
        try:
            response = self.llm.invoke(prompt).strip()
            keywords = [kw.strip() for kw in response.split(',') if kw.strip()]
            logger.info(f"[derive_keywords] extracted {len(keywords)} keywords: {keywords}")
            return keywords[:8]  # Limit to 8
        except Exception as e:
            logger.error(f"[derive_keywords] error: {e}")
            return ["policy improvement", "evidence-based policy"]  # Fallback

    def search_evidence(self, keywords: List[str]) -> List[Dict]:
        """Search Google for relevant web pages and documents using keywords. Prioritizes academic sources... (existing docstring)"""
        all_results = []

        # Step 1: Academic search with error handling
        academic_sites = "site:nih.gov OR site:who.int OR site:jstor.org OR site:sciencedirect.com OR site:pubmed.ncbi.nlm.nih.gov"
        academic_results = []
        for kw in keywords:
            try:
                academic_query = f'"{kw}" {academic_sites}'
                results = self.google_search.search_google(query=academic_query, num_results=5)
                academic_results.extend(results)
                logger.debug(f"[search_evidence] academic search for '{kw}': {len(results)} results")
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    logger.warning(f"[search_evidence] Rate limit hit for academic '{kw}'; skipping")
                    break  # Stop loop to avoid more 429s
                else:
                    raise  # Re-raise other errors
            except ValueError as e:
                logger.warning(f"[search_evidence] invalid academic topic for '{kw}': {e}")
            except Exception as e:
                logger.error(f"[search_evidence] academic search failed for '{kw}': {e}")

        # Dedupe academics
        seen_urls = set()
        academic_results = [r for r in academic_results if r['url'] not in seen_urls and not seen_urls.add(r['url'])]
        all_results.extend(academic_results)
        logger.info(f"[search_evidence] collected {len(academic_results)} academic results")

        if len(academic_results) < 5:
            logger.warning(
                f"[search_evidence] low academic yield ({len(academic_results)}); supplementing with general search")

        # Step 2: General search with error handling
        general_results = []
        for kw in keywords:
            try:
                results = self.google_search.search_google(query=kw, num_results=5)
                non_academic = [r for r in results if not any(site in r['url'] for site in
                                                              ['nih.gov', 'who.int', 'jstor.org', 'sciencedirect.com',
                                                               'pubmed.ncbi.nlm.nih.gov'])]
                general_results.extend(non_academic)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    logger.warning(f"[search_evidence] Rate limit hit for general '{kw}'; skipping remaining")
                    break  # Stop to prevent quota burn
                else:
                    raise
            except ValueError as e:
                logger.warning(f"[search_evidence] invalid topic for '{kw}': {e}")
            except Exception as e:
                logger.error(f"[search_evidence] search failed for '{kw}': {e}")

        # Dedupe generals
        seen_urls = set()
        general_results = [r for r in general_results if r['url'] not in seen_urls and not seen_urls.add(r['url'])]
        all_results.extend(general_results[:5])

        # Step 3: Ranking (unchanged)
        kw_concat = ' '.join(keywords).lower()

        def relevance_score(r):
            score = len([w for w in r['snippet'].lower().split() if w in kw_concat])
            if any(site in r['url'] for site in
                   ['nih.gov', 'who.int', 'jstor.org', 'sciencedirect.com', 'pubmed.ncbi.nlm.nih.gov']):
                score += 1.0
            return score

        all_results.sort(key=relevance_score, reverse=True)
        final_results = all_results[:10]
        academic_count = sum(1 for r in final_results if any(site in r['url'] for site in
                                                             ['nih.gov', 'who.int', 'jstor.org', 'sciencedirect.com',
                                                              'pubmed.ncbi.nlm.nih.gov']))
        logger.info(
            f"[search_evidence] ranked {len(final_results)} results ({academic_count} academic; includes web pages)")

        return final_results

    def generate_suggestions(self, policy_text: str, evidence_results: List[Dict]) -> str:
        """Use LLM (inspired by PolicyBuilder) to generate improvement suggestions with evidence citations."""
        evidence_summary = "\n".join(
            [f"- {r['title']} ({r['source']}): {r['snippet'][:200]}..." for r in evidence_results])
        prompt = f"""
        You are a policy improvement assistant (like a drafting expert).

        POLICY TEXT: {policy_text[:5000]}

        RELEVANT EVIDENCE (from searches on derived keywords; ranked by relevance with academics first; includes web pages and documents):
        {evidence_summary or "No evidence found; suggest general improvements."}

        TASK:
        - Analyze the policy for gaps (e.g., missing data, weak sections, implementation issues).
        - Suggest 6-10 specific, evidence-based improvements (e.g., "Add data on X from [source]").
        - Structure as: Title, then numbered list with explanation + evidence tie-in.
        - Keep professional, concise, and actionable for researchers.
        - End with a revised outline if relevant.
        """
        try:
            suggestions = self.policy_builder.llm.invoke(prompt)  # Reuse llm from builder
            logger.info("[generate_suggestions] generated suggestions")
            return suggestions
        except Exception as e:
            logger.error(f"[generate_suggestions] error: {e}")
            return "Error generating suggestions. Please try again."

    # Add this method to PolicyAnalyzer class
    def _search_with_bypass(self, keywords: List[str]) -> List[Dict]:
        """Bypass topic validation for generic policy keywords, falling back to broad searches."""
        all_results = []
        for kw in keywords:
            if self.google_search.validate_topic(kw):
                # Original flow if valid
                try:
                    results = self.google_search.search_google(query=kw, num_results=5)
                    all_results.extend(results)
                except ValueError:
                    pass  # Skip invalid
            else:
                # Bypass: Search with appended health/policy terms for relevance
                fallback_query = f"{kw} evidence-based policy"  # Broad fallback
                if self.google_search.validate_topic(fallback_query):
                    try:
                        results = self.google_search.search_google(query=fallback_query, num_results=3)
                        all_results.extend(results)
                    except ValueError:
                        pass
                logger.debug(f"[search_bypass] skipped '{kw}', used fallback '{fallback_query}'")

        # Dedupe and rank as before
        seen_urls = set()
        unique = [r for r in all_results if r['url'] not in seen_urls and not seen_urls.add(r['url'])]
        # Reuse ranking logic from search_evidence
        kw_concat = ' '.join(keywords).lower()

        def score(r):
            s = len([w for w in r['snippet'].lower().split() if w in kw_concat])
            if any(site in r['url'] for site in
                   ['nih.gov', 'who.int', 'jstor.org', 'sciencedirect.com', 'pubmed.ncbi.nlm.nih.gov']):
                s += 1.0
            return s

        unique.sort(key=score, reverse=True)
        return unique[:10]

