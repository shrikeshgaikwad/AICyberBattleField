"""
LLM Client - Abstraction over LLM Providers
=============================================
Provides a unified interface to communicate with local (Ollama) or remote LLMs.
Includes retries, timeout handling, response parsing, and caching.
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Standardized LLM response."""

    content: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_duration_ms: float = 0.0
    success: bool = True
    error: Optional[str] = None
    cached: bool = False
    raw: dict = field(default_factory=dict)


class LLMClient:
    """
    Unified LLM client supporting Ollama.
    Handles retries, timeouts, and optional Redis caching.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
        max_retries: Optional[int] = None,
    ):
        self.base_url = (base_url or getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or getattr(settings, "OLLAMA_MODEL", "llama3.1:8b")
        self.timeout = timeout or getattr(settings, "LLM_TIMEOUT", 120)
        self.max_retries = max_retries or getattr(settings, "LLM_MAX_RETRIES", 3)

    def _cache_key(self, system_prompt: str, user_prompt: str) -> str:
        combined = f"{self.model}:{system_prompt}:{user_prompt}"
        return f"llm_cache:{hashlib.sha256(combined.encode()).hexdigest()}"

    def query(
        self,
        user_prompt: str,
        system_prompt: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        use_cache: bool = True,
        format_json: bool = False,
    ) -> LLMResponse:
        """
        Send a prompt to the LLM and return a structured response.

        Args:
            user_prompt: The user's message/question.
            system_prompt: System-level instructions for the LLM.
            temperature: Creativity (0.0 = deterministic, 1.0 = creative).
            max_tokens: Maximum tokens in response.
            use_cache: Whether to cache/retrieve from cache.
            format_json: If True, request JSON output format.

        Returns:
            LLMResponse with content and metadata.
        """
        # Check cache first
        if use_cache:
            cache_key = self._cache_key(system_prompt, user_prompt)
            cached_content = cache.get(cache_key)
            if cached_content:
                logger.info("LLM cache hit")
                return LLMResponse(
                    content=cached_content,
                    model=self.model,
                    cached=True,
                    success=True,
                )

        # Build request payload
        payload = {
            "model": self.model,
            "messages": [],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        if format_json:
            payload["format"] = "json"

        if system_prompt:
            payload["messages"].append({"role": "system", "content": system_prompt})
        payload["messages"].append({"role": "user", "content": user_prompt})

        # Execute with retries
        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                start_time = time.time()
                response = requests.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                    timeout=self.timeout,
                )
                duration_ms = (time.time() - start_time) * 1000

                if response.status_code == 200:
                    data = response.json()
                    content = data.get("message", {}).get("content", "")

                    result = LLMResponse(
                        content=content,
                        model=data.get("model", self.model),
                        total_duration_ms=duration_ms,
                        success=True,
                        raw=data,
                    )

                    # Cache the result
                    if use_cache and content:
                        cache.set(cache_key, content, timeout=3600)

                    logger.info(f"LLM query success (attempt {attempt}, {duration_ms:.0f}ms)")
                    return result
                else:
                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    logger.warning(f"LLM query failed (attempt {attempt}): {last_error}")

            except requests.exceptions.Timeout:
                last_error = f"Timeout after {self.timeout}s"
                logger.warning(f"LLM query timeout (attempt {attempt})")
            except requests.exceptions.ConnectionError:
                last_error = "Connection refused - is Ollama running?"
                logger.warning(f"LLM connection error (attempt {attempt})")
            except Exception as e:
                last_error = str(e)
                logger.error(f"LLM query error (attempt {attempt}): {e}", exc_info=True)

            if attempt < self.max_retries:
                wait = 2 ** attempt
                logger.info(f"Retrying in {wait}s...")
                time.sleep(wait)

        return LLMResponse(
            content="",
            model=self.model,
            success=False,
            error=last_error,
        )

    def query_json(
        self,
        user_prompt: str,
        system_prompt: str = "",
        temperature: float = 0.3,
        **kwargs,
    ) -> dict:
        """
        Query LLM and parse response as JSON.
        Returns parsed dict or empty dict on failure.
        """
        response = self.query(
            user_prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            format_json=True,
            **kwargs,
        )

        if not response.success:
            logger.error(f"LLM JSON query failed: {response.error}")
            return {}

        try:
            return json.loads(response.content)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            content = response.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            try:
                return json.loads(content.strip())
            except json.JSONDecodeError:
                logger.error(f"Failed to parse LLM response as JSON: {content[:200]}")
                return {}

    def is_available(self) -> bool:
        """Check if the LLM server is reachable."""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self) -> list:
        """List available models on the Ollama server."""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if r.status_code == 200:
                return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            pass
        return []
