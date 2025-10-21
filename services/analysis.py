# analysis.py
import logging
import os
import re
import json
from typing import List, Dict

import numpy as np
from flask import current_app

from models.document import POLICY_TEXTS_IN_MEMORY, FRAMEWORK_TEXTS_IN_MEMORY
from models.llm import OpenAI_LLM
from models.search import SearchEngine
from models.models import db, Codebook, Code, SubCode, SubSubCode, Media

logger = logging.getLogger(__name__)


class AnalysisService:
    def __init__(self, doc_processor=None):
        self.llm = OpenAI_LLM(
            model_name="gpt-4o",
            temperature=0.0,
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )
        self.search_engine = SearchEngine()
        from models.document import DocumentProcessor
        self.doc_processor = doc_processor if doc_processor else DocumentProcessor()
        logger.info("[analysis] service initialized")

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for a given text."""
        word_count = len(text.split())
        return int(word_count * 1.5)

    def extract_codebook_codes(self, codebook_id: int) -> List[Dict[str, str]]:
        """Extract codes and their descriptions from a codebook."""
        try:
            codebook = db.session.get(Codebook, codebook_id)
            if not codebook:
                logger.error(f"Codebook with ID {codebook_id} not found")
                return [{"code": "General", "description": "Codebook not found."}]

            codes = []
            for code in codebook.codes:
                codes.append({
                    "code": code.code,
                    "description": code.description or "No description provided.",
                    "level": "code"
                })
                for subcode in code.subcodes:
                    codes.append({
                        "code": code.code,
                        "subcode": subcode.subcode,
                        "description": subcode.description or "No description provided.",
                        "level": "subcode"
                    })
                    for subsubcode in subcode.subsubcodes:
                        codes.append({
                            "code": code.code,
                            "subcode": subcode.subcode,
                            "subsubcode": subsubcode.subsubcode,
                            "description": subsubcode.description or "No description provided.",
                            "level": "subsubcode"
                        })

            if not codes:
                logger.warning(f"No codes found in codebook ID {codebook_id}")
                return [{"code": "General", "description": "No codes defined in the codebook."}]

            return codes

        except Exception as e:
            logger.error(f"Error extracting codes for codebook ID {codebook_id}: {str(e)}")
            return [{"code": "General", "description": f"Error extracting codes: {str(e)}"}]

    def generate_analysis_prompt(
        self,
        code: str,
        description: str,
        subcode: str = None,
        policy_chunks: List[tuple] = None
    ) -> str:
        """Generate a detailed LLM prompt for analyzing policy chunks against a code."""
        policy_text_blob = ''.join([
            f"\n--- {doc} ---\n[Chunk #{cid}]: {txt}\n"
            for doc, txt, cid in policy_chunks if txt.strip()
        ]) if policy_chunks else "No policy chunks available."

        prompt = f"""
You are an expert policy analyst tasked with identifying excerpts from policy documents that align with a codebook code.

CODEBOOK CODE:
- Code: {code}
- Description: {description}
{f"- Subcode: {subcode}" if subcode else ""}

TASK:
1. Review the provided policy document chunks and identify up to 3 excerpts that best align with the code's description.
2. An excerpt is considered relevant if it contains content that directly or indirectly relates to the themes, concepts, or keywords in the code description.
3. Format each excerpt EXACTLY as:
   - [Document Name] [Chunk #ID]: "exact excerpt"
4. After each excerpt, provide an analysis in this EXACT format:
   ### Analysis for {code}{" - " + subcode if subcode else ""}
   - Alignment: Explain how the excerpt aligns with the code's description: "{description}" (max 3 sentences).
   - Strengths: Bullet list of specific strengths of the policy content relative to the code.
   - Weaknesses: Bullet list of specific weaknesses or gaps in the policy content relative to the code.
5. If no relevant content is found, state: "No relevant content found for code '{code}'{f' - {subcode}' if subcode else ''}."
6. Use ONLY the provided chunks for quotes, and ensure excerpts are verbatim from the text.
7. Consider synonyms, related concepts, or broader interpretations of the code description to maximize relevance.

POLICY CHUNKS:
{policy_text_blob}
"""
        logger.debug(
            f"[analysis] generated prompt for code='{code}'{f' subcode={subcode}' if subcode else ''}: {prompt[:500]}..."
        )
        return prompt

    def analyze_single_code(
        self,
        code_info: Dict,
        selected_policy_chunks: List[tuple],
        codebook_id: int,
        project_id: int
    ) -> List[Dict]:
        """Analyze policy chunks against a single code/subcode."""
        code = code_info["code"]
        description = code_info["description"]
        subcode = code_info.get("subcode")
        level = code_info["level"]
        all_excerpts = []
        used_chunk_ids = set()

        logger.info(
            f"[analysis] processing code='{code}'{f' subcode={subcode}' if subcode else ''} description='{description}'"
        )

        # Estimate token usage
        combined_text = description + "\n".join([txt for _, txt, _ in selected_policy_chunks])
        approximate_tokens = self.estimate_tokens(combined_text)
        TOKEN_LIMIT = 10000

        if approximate_tokens > TOKEN_LIMIT:
            query = f"{code}: {description}" + (f" - {subcode}" if subcode else "")
            selected_policy_chunks = self.doc_processor.retrieve_top_k_chunks(
                query=query, top_k=10, is_framework=False
            )
            logger.info(f"[analysis] token limit exceeded, using top_k=10 chunks for code='{code}'")

        prompt = self.generate_analysis_prompt(code, description, subcode, selected_policy_chunks)

        try:
            raw_output = self.llm.invoke(prompt)
            logger.debug(
                f"[analysis] LLM output for code='{code}'{f' subcode={subcode}' if subcode else ''}: {raw_output[:500]}..."
            )

            # Regex to handle optional brackets around doc_name
            excerpt_pattern = re.compile(r'- \[?(.+?)\]?\s*\[Chunk #(\d+)\]: "(.+?)"')
            alignment_pattern = re.compile(r'- Alignment: (.+?)(?=(?:\n- Strengths:|$))', re.DOTALL)
            strengths_pattern = re.compile(r'- Strengths:\n((?:- .+\n)*)', re.MULTILINE)
            weaknesses_pattern = re.compile(r'- Weaknesses:\n((?:- .+\n)*)', re.MULTILINE)

            matches = excerpt_pattern.findall(raw_output)
            alignment_match = alignment_pattern.search(raw_output)
            strengths_match = strengths_pattern.search(raw_output)
            weaknesses_match = weaknesses_pattern.search(raw_output)

            alignment_expl = alignment_match.group(1).strip() if alignment_match else \
                f"Alignment with {code}{f' - {subcode}' if subcode else ''}"
            strengths = [s.strip() for s in strengths_match.group(1).split('\n') if s.strip().startswith('-')] \
                if strengths_match else []
            weaknesses = [w.strip() for w in weaknesses_match.group(1).split('\n') if w.strip().startswith('-')] \
                if weaknesses_match else []

            for doc_name, chunk_id, text in matches:
                doc_name = doc_name.strip('[]').strip()
                text_clean = text.strip()
                key = f"{doc_name}:{chunk_id}"
                if key in used_chunk_ids:
                    continue

                similarity = self.doc_processor.calculate_similarity(text_clean, description)
                logger.info(
                    f"[analysis] excerpt candidate: doc={doc_name} chunk_id={chunk_id} similarity={similarity:.2f} text={text_clean[:100]}..."
                )

                if similarity >= 0.2:
                    media = db.session.query(Media).filter_by(
                        filename=doc_name, project_id=project_id
                    ).first()
                    if media:
                        strengths_text = "\n".join(strengths) if strengths else "None"
                        weaknesses_text = "\n".join(weaknesses) if weaknesses else "None"
                        explanation = (
                            f"{alignment_expl}\n"
                            f"Strengths:\n{strengths_text}\n"
                            f"Weaknesses:\n{weaknesses_text}"
                        )

                        excerpt_data = {
                            "doc": doc_name,
                            "chunk_id": int(chunk_id),
                            "text": text_clean,
                            "code": code,
                            "subcode": subcode,
                            "codebook_id": codebook_id,
                            "media_id": media.id,
                            "explanation": explanation,
                        }

                        validated_excerpts = self.doc_processor.validate_excerpts(doc_name, [excerpt_data])
                        if validated_excerpts:
                            all_excerpts.append(validated_excerpts[0])
                            used_chunk_ids.add(key)
                            logger.info(
                                f"[analysis] excerpt validated: doc={doc_name} chunk_id={chunk_id} media_id={media.id}"
                            )
                        else:
                            logger.warning(
                                f"[analysis] excerpt validation failed: doc={doc_name} chunk_id={chunk_id}"
                            )
                    else:
                        logger.warning(f"[analysis] media not found for doc={doc_name} project_id={project_id}")
                else:
                    logger.warning(
                        f"[analysis] excerpt rejected due to low similarity: doc={doc_name} chunk_id={chunk_id} similarity={similarity:.2f}"
                    )

            if not matches:
                logger.info(f"[analysis] no excerpts found for code='{code}'{f' subcode={subcode}' if subcode else ''}")
                all_excerpts.append({
                    "doc": "N/A",
                    "chunk_id": -1,
                    "text": f"No relevant content found for code '{code}'{f' - {subcode}' if subcode else ''}.",
                    "code": code,
                    "subcode": subcode,
                    "codebook_id": codebook_id,
                    "media_id": None,
                    "explanation": f"No policy content aligns with code '{code}'{f' - {subcode}' if subcode else ''}."
                })

        except Exception as e:
            logger.error(
                f"[analysis] error analyzing code='{code}'{f' subcode={subcode}' if subcode else ''}: {str(e)}"
            )
            all_excerpts.append({
                "doc": "N/A",
                "chunk_id": -1,
                "text": f"No excerpt for code '{code}' due to error.",
                "code": code,
                "subcode": subcode,
                "codebook_id": codebook_id,
                "media_id": None,
                "explanation": f"Error occurred during analysis: {str(e)}"
            })

        return all_excerpts

    def analyze_media(self, media_ids: List[int], codebook_id: int, project_id: int) -> Dict:
        """Analyze media files against a codebook and generate excerpts."""
        logger.info(
            f"[analysis] start project={project_id} codebook={codebook_id} media_batch={len(media_ids)} ids={media_ids}"
        )

        selected_policy_chunks = []

        for media_id in media_ids:
            media = db.session.get(Media, media_id)
            if not media or media.project_id != project_id:
                logger.warning(f"[analysis] skip media_id={media_id}: not found or wrong project")
                continue

            filename = media.filename
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            logger.info(f"[analysis] loading file: {file_path}")

            if not os.path.exists(file_path):
                logger.error(f"[analysis] file missing: {file_path}")
                continue

            try:
                if filename.lower().endswith('.pdf'):
                    text = self.doc_processor.extract_text_from_pdf(file_path)
                elif filename.lower().endswith('.docx'):
                    text = self.doc_processor.extract_text_from_docx(file_path)
                else:
                    logger.error(f"[analysis] unsupported type: {filename}")
                    continue

                chunks = self.doc_processor.split_text_into_chunks(text)
                POLICY_TEXTS_IN_MEMORY[filename] = chunks
                self.doc_processor.store_doc_chunks_in_faiss(filename, chunks, is_framework=False)
                selected_policy_chunks.extend([(filename, chunk_text, idx) for idx, chunk_text in enumerate(chunks)])
                logger.info(f"[analysis] {filename}: chunks={len(chunks)}")

            except Exception as e:
                logger.exception(f"[analysis] load failed for {filename}: {e}")
                continue

        if not selected_policy_chunks:
            logger.error("No policy document chunks available for analysis")
            return {"excerpts": [], "explanation": "No policy documents loaded or accessible."}

        codes_info = self.extract_codebook_codes(codebook_id)
        if not codes_info or codes_info[0].get("code") == "General":
            return {"excerpts": [], "explanation": "No valid codes found in the codebook."}

        all_excerpts = []
        for code_info in codes_info:
            excerpts = self.analyze_single_code(code_info, selected_policy_chunks, codebook_id, project_id)
            all_excerpts.extend(excerpts)

        logger.info(f"[analysis] done: total_excerpts={len(all_excerpts)}")
        return {
            "excerpts": all_excerpts,
            "explanation": f"Analysis completed for {len(codes_info)} codes in codebook ID {codebook_id}."
        }

    def extract_framework_variables(self, framework_text: str, framework_name: str) -> List[Dict[str, str]]:
        """
        Extracts dimensions/variables and their explanations from a framework document.
        Returns a list of dictionaries with 'variable' and 'explanation' keys.
        """
        prompt = f"""
You are an expert policy analyst. Extract the key dimensions (or variables) and their explanations from the framework document titled "{framework_name}".

RULES:
1. Assume the framework is in table format: each row = one variable/dimension.
2. Extract only rows that describe policy assessment dimensions (e.g., Political, Economic, etc.).
3. Ignore headings or repeated labels.

OUTPUT FORMAT:
Return a clean JSON array like this:
[
    {{
        "variable": "Dimension Name",
        "explanation": "Brief explanation of what this dimension means or assesses."
    }},
    ...
]

Only output valid JSON. Do not include any markdown (```json) or comments.

FRAMEWORK TEXT:
{framework_text[:7000]}
"""

        try:
            response = self.llm.invoke(prompt).strip()

            if response.startswith("```json"):
                response = response.replace("```json", "").replace("```", "").strip()

            variables = json.loads(response)

            validated = []
            for item in variables:
                if not isinstance(item, dict):
                    continue
                var = item.get("variable", "").strip()
                expl = item.get("explanation", "").strip()
                if var and expl:
                    validated.append({"variable": var, "explanation": expl})

            if not validated:
                raise ValueError("No valid variable-explanation pairs found.")

            seen = set()
            final_vars = []
            for v in validated:
                if v["variable"] not in seen:
                    seen.add(v["variable"])
                    final_vars.append(v)

            return final_vars

        except json.JSONDecodeError as e:
            logger.error(f"LLM output was not valid JSON for {framework_name}: {e}")
            return [{
                "variable": "General",
                "explanation": "Could not extract structured framework dimensions due to malformed JSON."
            }]
        except Exception as e:
            logger.error(f"Error extracting framework variables for {framework_name}: {str(e)}")
            return [{
                "variable": "General",
                "explanation": "Error during framework extraction."
            }]
