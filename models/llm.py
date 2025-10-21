# models/llm.py
from pydantic import BaseModel
from langchain.llms.base import LLM
from typing import Optional, List
import logging
import os

import httpx
from openai import OpenAI
from openai._exceptions import APIError, RateLimitError, APIConnectionError, AuthenticationError

logger = logging.getLogger(__name__)

class OpenAI_LLM(LLM, BaseModel):
    model_name: str = "gpt-4o"
    temperature: float = 0.0
    openai_api_key: Optional[str] = None
    request_timeout: float = 60.0
    max_retries: int = 2

    class Config:
        extra = "allow"

    @property
    def _llm_type(self) -> str:
        return "openai_chat"

    def _call(self, prompt: str, stop: Optional[List[str]] = None) -> str:
        if not self.openai_api_key:
            raise ValueError("OpenAI API key is not set.")

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a Policy Analysis expert. "
                    "You MUST NOT fabricate or hallucinate any text."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        text = self.get_completion_from_messages(
            messages=messages,
            model=self.model_name,
            temperature=self.temperature,
            stop=stop,
        )
        return text if text else "I'm sorry, but I was unable to generate a response."

    def _build_http_client(self) -> httpx.Client:
        """
        Build an httpx client that supports proxies via env or OPENAI_HTTP_PROXY,
        with timeouts and a small connection pool.
        """
        # Respect standard env proxies or a custom env (OPENAI_HTTP_PROXY)
        proxy = os.getenv("OPENAI_HTTP_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        timeout = httpx.Timeout(self.request_timeout)
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)

        if proxy:
            return httpx.Client(proxies=proxy, timeout=timeout, limits=limits)
        return httpx.Client(timeout=timeout, limits=limits)

    def get_completion_from_messages(
        self,
        messages,
        model: str = "gpt-4o",
        temperature: float = 0.0,
        stop=None,
    ) -> Optional[str]:
        """
        Call the OpenAI Chat Completions API using the v1 SDK.
        Avoids unsupported kwargs like `proxies=...`.
        """
        try:
            http_client = self._build_http_client()
            client = OpenAI(
                api_key=self.openai_api_key,
                http_client=http_client,
                # You can also set organization/project via env: OPENAI_ORG_ID / OPENAI_PROJECT
                # organization=os.getenv("OPENAI_ORG_ID"),
                # project=os.getenv("OPENAI_PROJECT"),
            )

            # simple retry loop
            last_err = None
            for attempt in range(self.max_retries + 1):
                try:
                    resp = client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=temperature,
                        stop=stop,
                    )
                    return (resp.choices[0].message.content or "").strip()
                except (RateLimitError, APIConnectionError, APIError) as e:
                    last_err = e
                    logger.warning(f"OpenAI transient error (attempt {attempt+1}/{self.max_retries+1}): {e}")
                except AuthenticationError as e:
                    logger.error("OpenAI auth error: check OPENAI_API_KEY, org/project access.")
                    raise
            # out of retries
            if last_err:
                logger.error(f"OpenAI API error after retries: {last_err}")
            return None

        except TypeError as e:
            # This is where you'd see: "__init__() got an unexpected keyword argument 'proxies'"
            # if someone mistakenly passed proxies to OpenAI(...).
            logger.error(f"OpenAI client init TypeError: {e}. "
                         f"Remove unsupported kwargs (e.g., 'proxies') from client initialization.")
            return None
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return None

    @property
    def _identifying_params(self) -> dict:
        return {"model_name": self.model_name, "temperature": self.temperature}
