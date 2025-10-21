import logging
import faiss
from bs4 import BeautifulSoup
import os
import requests
from typing import List, Tuple, Optional
import numpy as np
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

class SearchEngine:
    def __init__(self):
        self.embedding_model = SentenceTransformer("models/all-MiniLM-L6-v2")
        self.search_index = None

    def google_search(self, query: str, num_results: int = 5) -> List[Tuple[str, str]]:
        url = f"https://www.google.com/search?q={query}"
        headers = {"User-Agent": "Mozilla/5.0"}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            results = []
            for g in soup.find_all('div', class_='tF2Cxc'):
                title = g.find('h3').text if g.find('h3') else "No Title"
                link = g.find('a')['href'] if g.find('a') else "No Link"
                results.append((title, link))
            return results[:num_results]
        except Exception as e:
            logger.error(f"Google search failed: {e}")
            return []

    def store_search_results(self, query: str, results: List[Tuple[str, str]], index_path: str = "google_search.faiss") -> None:
        if not results:
            logger.info("No results to store in FAISS.")
            return

        titles = [r[0] for r in results]
        embeddings = self.embedding_model.encode(titles, convert_to_numpy=True)
        if embeddings.ndim == 1:
            embeddings = embeddings[None, :]

        if os.path.exists(index_path):
            self.search_index = faiss.read_index(index_path)
        else:
            self.search_index = faiss.IndexFlatL2(embeddings.shape[1])

        self.search_index.add(embeddings.astype('float32'))
        faiss.write_index(self.search_index, index_path)

    def search_indexed_results(self, query: str, index_path: str = "google_search.faiss") -> Optional[List[int]]:
        if not os.path.exists(index_path):
            logger.warning("No local search index found.")
            return None

        try:
            self.search_index = faiss.read_index(index_path)
            query_emb = self.embedding_model.encode([query], convert_to_numpy=True).astype('float32')
            distances, indices = self.search_index.search(query_emb, 5)
            return indices
        except Exception as e:
            logger.error(f"Error searching FAISS index: {e}")
            return None
