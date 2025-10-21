# document.py
import logging
import os
import shutil
from typing import List, Dict, Tuple
from flask import current_app
import faiss
import numpy as np
import pdfplumber
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

# Optional DOCX support
try:
    from docx import Document as _DocxDocument
except Exception:  # pragma: no cover
    _DocxDocument = None

# -----------------------------
# Global in-memory stores/index
# -----------------------------
POLICY_TEXTS_IN_MEMORY: Dict[str, List[str]] = {}
FRAMEWORK_TEXTS_IN_MEMORY: Dict[str, List[str]] = {}

policy_index = None            # faiss.Index or None
framework_index = None         # faiss.Index or None
policy_metadata: List[Tuple[str, int, str]] = []     # (doc_name, chunk_id, chunk_text)
framework_metadata: List[Tuple[str, int, str]] = []  # (doc_name, chunk_id, chunk_text)

# Single embedding model shared across instances
embedding_model = SentenceTransformer("models/all-MiniLM-L6-v2")


class DocumentProcessor:
    """
    Handles reading PDFs/DOCX, chunking, FAISS storage/search, and in-memory bookkeeping.
    Directories default to your current app layout.
    """

    def __init__(self, policies_dir: str = "policy_uploaded_files", frameworks_dir: str = "frame_uploaded_files"):
        # mirror globals onto the instance so callers can read via self.*
        self.policy_index = globals()["policy_index"]
        self.framework_index = globals()["framework_index"]
        self.policy_metadata = globals()["policy_metadata"]
        self.framework_metadata = globals()["framework_metadata"]
        self.embedding_model = embedding_model

        self.policies_dir = policies_dir
        self.frameworks_dir = frameworks_dir
        os.makedirs(self.policies_dir, exist_ok=True)
        os.makedirs(self.frameworks_dir, exist_ok=True)

    # -----------------------------
    # Text extraction
    # -----------------------------
    def extract_text_from_pdf(self, pdf_path: str) -> str:
        """Extracts clean text from a PDF with pdfplumber."""
        try:
            text_parts: List[str] = []
            with pdfplumber.open(pdf_path) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text() or ""
                    page_text = page_text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
                    text_parts.append(" ".join(page_text.split()))
            text = " ".join([t for t in text_parts if t]).strip()
            if not text:
                logger.warning(f"No text extracted from PDF: {pdf_path}")
            return text
        except Exception as e:
            logger.error(f"PDF extract error for {pdf_path}: {e}")
            return ""

    def extract_text_from_docx(self, docx_path: str) -> str:
        """Extracts text from a DOCX using python-docx."""
        if _DocxDocument is None:
            raise RuntimeError("python-docx is required for DOCX extraction (pip install python-docx).")
        try:
            doc = _DocxDocument(docx_path)
            parts = [(p.text or "").strip() for p in doc.paragraphs]
            text = " ".join([t for t in parts if t])
            return " ".join(text.split())
        except Exception as e:
            logger.error(f"DOCX extract error for {docx_path}: {e}")
            return ""

    # -----------------------------
    # Utilities
    # -----------------------------
    @staticmethod
    def normalize_text_for_validation(text: str) -> str:
        return " ".join(text.lower().split()).replace("\n", " ").replace("\r", "").replace("\t", " ")

    @staticmethod
    def _word_overlap_ratio(a: str, b: str) -> float:
        A, B = set(a.split()), set(b.split())
        if not A or not B:
            return 0.0
        return len(A & B) / min(len(A), len(B))

    def split_text_into_chunks(
        self,
        text: str,
        chunk_size_words: int = 180,
        min_words: int = 25,
        max_words: int = 220,
    ) -> List[str]:
        """
        Greedy word-based chunking with soft bounds.
        """
        words = text.split()
        chunks: List[str] = []
        buf: List[str] = []

        for w in words:
            buf.append(w)
            if len(buf) >= chunk_size_words:
                chunks.append(" ".join(buf))
                buf = []
        if buf:
            chunks.append(" ".join(buf))

        # filter to reasonable lengths
        filtered = [c for c in chunks if min_words <= len(c.split()) <= max_words]
        # ensure at least something returns
        return filtered or ([" ".join(words[:max_words])] if words else [])

    # -----------------------------
    # FAISS storage
    # -----------------------------
    def store_doc_chunks_in_faiss(self, doc_name: str, chunks: List[str], is_framework: bool = False) -> None:
        """
        Encodes `chunks`, appends to (or creates) the appropriate FAISS index, and writes/updates metadata.
        """
        global policy_index, framework_index, policy_metadata, framework_metadata

        if not chunks:
            logger.warning(f"No chunks to store for {doc_name}")
            return

        emb = self.embedding_model.encode(chunks, convert_to_numpy=True).astype("float32")
        dim = emb.shape[1]

        if is_framework:
            index_path = os.path.join(self.frameworks_dir, f"{doc_name}_index.faiss")
            idx = faiss.read_index(index_path) if os.path.exists(index_path) else faiss.IndexFlatL2(dim)
            start = idx.ntotal
            idx.add(emb)
            faiss.write_index(idx, index_path)

            meta_path = os.path.join(self.frameworks_dir, f"{doc_name}_metadata.txt")
            with open(meta_path, "a", encoding="utf-8") as f:
                for i, chunk_text in enumerate(chunks):
                    f.write(f"{doc_name},{start + i},{chunk_text}\n")

            framework_index = idx
            self.framework_index = idx
            framework_metadata.extend([(doc_name, start + i, c) for i, c in enumerate(chunks)])
            self.framework_metadata = framework_metadata
            logger.info(f"Stored framework {doc_name}: +{len(chunks)} chunks")

        else:
            index_path = os.path.join(self.policies_dir, f"{doc_name}_index.faiss")
            idx = faiss.read_index(index_path) if os.path.exists(index_path) else faiss.IndexFlatL2(dim)
            start = idx.ntotal
            idx.add(emb)
            faiss.write_index(idx, index_path)

            meta_path = os.path.join(self.policies_dir, f"{doc_name}_metadata.txt")
            with open(meta_path, "a", encoding="utf-8") as f:
                for i, chunk_text in enumerate(chunks):
                    f.write(f"{doc_name},{start + i},{chunk_text}\n")

            policy_index = idx
            self.policy_index = idx
            policy_metadata.extend([(doc_name, start + i, c) for i, c in enumerate(chunks)])
            self.policy_metadata = policy_metadata
            logger.info(f"Stored policy {doc_name}: +{len(chunks)} chunks")

    # -----------------------------
    # Ingest single document (PDF/DOCX)
    # -----------------------------
    def analyse_one_document(self, document_path: str, is_framework: bool = False) -> str:
        """
        Copies the file into the appropriate dir, extracts text (PDF or DOCX), chunks, indexes.
        """
        if not os.path.exists(document_path):
            logger.error(f"File not found: {document_path}")
            return f"Error: File not found: {document_path}"

        ext = os.path.splitext(document_path)[1].lower()
        if ext not in (".pdf", ".docx"):
            logger.error(f"Invalid file type for {document_path}: Must be PDF or DOCX")
            return f"Error: The document must be a PDF or DOCX. Skipped {document_path}"

        doc_name = os.path.basename(document_path)
        dest_dir = self.frameworks_dir if is_framework else self.policies_dir
        dest_path = os.path.join(dest_dir, doc_name)

        # copy for persistence / later reload
        try:
            if os.path.abspath(document_path) != os.path.abspath(dest_path):
                shutil.copy(document_path, dest_path)
        except Exception as e:
            logger.error(f"Copy failed for {doc_name} -> {dest_path}: {e}")
            return f"Error copying {doc_name}: {e}"

        # extract
        text = self.extract_text_from_docx(dest_path) if ext == ".docx" else self.extract_text_from_pdf(dest_path)
        if not text:
            logger.warning(f"No text extracted from {dest_path}")
            return f"No text extracted from {dest_path}"

        chunks = self.split_text_into_chunks(text)
        self.store_doc_chunks_in_faiss(doc_name, chunks, is_framework=is_framework)
        kind = "Framework" if is_framework else "Policy"
        return f"{kind} doc analysis complete for {doc_name} ({len(chunks)} chunks)."

    # -----------------------------
    # Load from disk into memory
    # -----------------------------
    def _safe_reindex_if_missing(self, name: str, is_framework: bool) -> None:
        """If index/metadata are missing but the PDF/DOCX exists, re-run analyse_one_document."""
        base_dir = self.frameworks_dir if is_framework else self.policies_dir
        index_path = os.path.join(base_dir, f"{name}_index.faiss")
        meta_path = os.path.join(base_dir, f"{name}_metadata.txt")
        file_pdf = os.path.join(base_dir, f"{name}")
        if (not os.path.exists(index_path) or not os.path.exists(meta_path)) and os.path.exists(file_pdf):
            logger.warning(f"Index/metadata missing for {name}, reprocessing")
            res = self.analyse_one_document(file_pdf, is_framework=is_framework)
            if res.startswith("Error") or "No text extracted" in res:
                raise FileNotFoundError(f"Could not reprocess {name}: {res}")

    def load_policy(self, policy_name: str) -> None:
        global policy_index, policy_metadata, POLICY_TEXTS_IN_MEMORY
        self._safe_reindex_if_missing(policy_name, is_framework=False)

        index_path = os.path.join(self.policies_dir, f"{policy_name}_index.faiss")
        meta_path = os.path.join(self.policies_dir, f"{policy_name}_metadata.txt")
        if not (os.path.exists(index_path) and os.path.exists(meta_path)):
            raise FileNotFoundError(f"Policy index or metadata not found for {policy_name}")

        new_idx = faiss.read_index(index_path)
        if policy_index is None:
            policy_index = new_idx
        else:
            # merge vectors
            vecs = new_idx.reconstruct_n(0, new_idx.ntotal)
            policy_index.add(vecs)
        self.policy_index = policy_index

        with open(meta_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    doc_name, chunk_id, chunk_text = line.strip().split(",", 2)
                    POLICY_TEXTS_IN_MEMORY.setdefault(doc_name, []).append(chunk_text)
                    policy_metadata.append((doc_name, int(chunk_id), chunk_text))
                except ValueError as e:
                    logger.warning(f"Bad metadata line in {meta_path}: {line.strip()} ({e})")

        logger.info(f"Loaded policy {policy_name}. In memory: {list(POLICY_TEXTS_IN_MEMORY.keys())}")

    def load_framework(self, framework_name: str) -> None:
        global framework_index, framework_metadata, FRAMEWORK_TEXTS_IN_MEMORY
        self._safe_reindex_if_missing(framework_name, is_framework=True)

        index_path = os.path.join(self.frameworks_dir, f"{framework_name}_index.faiss")
        meta_path = os.path.join(self.frameworks_dir, f"{framework_name}_metadata.txt")
        if not (os.path.exists(index_path) and os.path.exists(meta_path)):
            raise FileNotFoundError(f"Framework index or metadata not found for {framework_name}")

        # reset before load (keeps framework space clean)
        FRAMEWORK_TEXTS_IN_MEMORY.clear()
        framework_metadata.clear()

        framework_index = faiss.read_index(index_path)
        self.framework_index = framework_index

        with open(meta_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    doc_name, chunk_id, chunk_text = line.strip().split(",", 2)
                    FRAMEWORK_TEXTS_IN_MEMORY.setdefault(doc_name, []).append(chunk_text)
                    framework_metadata.append((doc_name, int(chunk_id), chunk_text))
                except ValueError as e:
                    logger.warning(f"Bad metadata line in {meta_path}: {line.strip()} ({e})")

        logger.info(f"Loaded framework {framework_name} (vectors: {framework_index.ntotal}).")

    # -----------------------------
    # Retrieval
    # -----------------------------
    def retrieve_top_k_chunks(self, query: str, top_k: int = 5, is_framework: bool = False) -> List[Tuple[str, str, int]]:
        try:
            idx = self.framework_index if is_framework else self.policy_index
            meta = self.framework_metadata if is_framework else self.policy_metadata

            if idx is None or idx.ntotal == 0 or not meta:
                logger.warning(f"No {'framework' if is_framework else 'policy'} index or metadata available.")
                return []

            q = self.embedding_model.encode([query], convert_to_numpy=True).astype("float32")
            distances, indices = idx.search(q, top_k)

            out: List[Tuple[str, str, int]] = []
            for pos in indices[0]:
                if 0 <= pos < len(meta):
                    doc_name, chunk_id, chunk_text = meta[pos]
                    out.append((doc_name, chunk_text, chunk_id))
                else:
                    logger.debug(f"Index {pos} out of bounds (meta size {len(meta)})")
            return out
        except Exception as e:
            logger.error(f"Retrieval error: {e}")
            return []

    # -----------------------------
    # Memory/index maintenance
    # -----------------------------
    def remove_policy_from_memory(self, policy_name: str) -> None:
        global POLICY_TEXTS_IN_MEMORY, policy_metadata
        if policy_name in POLICY_TEXTS_IN_MEMORY:
            del POLICY_TEXTS_IN_MEMORY[policy_name]
            self.policy_metadata = [m for m in self.policy_metadata if m[0] != policy_name]
            logger.info(f"Removed policy {policy_name} from memory")
        else:
            logger.warning(f"Policy {policy_name} not in memory")

    def remove_framework_from_memory(self, framework_name: str) -> None:
        global FRAMEWORK_TEXTS_IN_MEMORY, framework_metadata
        if framework_name in FRAMEWORK_TEXTS_IN_MEMORY:
            del FRAMEWORK_TEXTS_IN_MEMORY[framework_name]
            self.framework_metadata = [m for m in self.framework_metadata if m[0] != framework_name]
            if not FRAMEWORK_TEXTS_IN_MEMORY:
                self.reset_framework_index()
            logger.info(f"Removed framework {framework_name} from memory")
        else:
            logger.warning(f"Framework {framework_name} not in memory")

    def reset_policy_index(self) -> None:
        global policy_index, policy_metadata, POLICY_TEXTS_IN_MEMORY
        if policy_index:
            policy_index.reset()
        policy_metadata.clear()
        POLICY_TEXTS_IN_MEMORY.clear()
        self.policy_index = None
        logger.info("Policy index and metadata reset.")

    # document.py (add to DocumentProcessor class)
    def calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate cosine similarity between two texts using the embedding model."""
        embeddings = self.embedding_model.encode([text1, text2], convert_to_numpy=True)
        cosine_sim = np.dot(embeddings[0], embeddings[1]) / (
                    np.linalg.norm(embeddings[0]) * np.linalg.norm(embeddings[1]))
        return float(cosine_sim)
    def reset_framework_index(self) -> None:
        global framework_index, framework_metadata, FRAMEWORK_TEXTS_IN_MEMORY
        if framework_index:
            framework_index.reset()
        framework_metadata.clear()
        FRAMEWORK_TEXTS_IN_MEMORY.clear()
        self.framework_index = None
        logger.info("Framework index and metadata reset.")

    # -----------------------------
    # Validation helpers (optional)
    # -----------------------------
    def validate_excerpts(self, doc_name: str, excerpts: List[Dict]) -> List[Dict]:
        """Validate that excerpts exist in the source document."""
        try:
            # Use the configured upload folder for policy documents
            doc_path = os.path.join(current_app.config['UPLOAD_FOLDER'], doc_name)
            logger.debug(f"[validate_excerpts] attempting to load doc={doc_name} from path={doc_path}")

            if not os.path.exists(doc_path):
                logger.error(f"Cannot validate excerpts: {doc_path} not found")
                return []

            # Load document text
            text = self.extract_text_from_pdf(doc_path)
            if not text:
                logger.error(f"No text extracted from {doc_path}")
                return []

            validated = []
            for excerpt in excerpts:
                excerpt_text = excerpt.get('text', '')
                if not excerpt_text:
                    logger.warning(f"[validate_excerpts] empty excerpt text for doc={doc_name}")
                    continue

                # Case-insensitive substring check
                if excerpt_text.lower() in text.lower():
                    validated.append(excerpt)
                    logger.info(f"[validate_excerpts] validated excerpt for doc={doc_name}: {excerpt_text[:50]}...")
                else:
                    logger.warning(f"[validate_excerpts] excerpt not found in doc={doc_name}: {excerpt_text[:50]}...")

            return validated

        except Exception as e:
            logger.error(f"[validate_excerpts] error validating excerpts for {doc_name}: {str(e)}")
            return []
