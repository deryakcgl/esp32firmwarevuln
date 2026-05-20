from __future__ import annotations

import logging
from typing import List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)


def resolve_ollama_model(requested: str, available: List[str]) -> str:
    req = (requested or "").strip()
    if not req:
        return req
    if req in available:
        return req
    base = req.split(":")[0]
    for name in available:
        if name == base or name.startswith(base + ":"):
            return name
    return req


def check_ollama(
    base_url: str = "http://localhost:11434",
    model: Optional[str] = None,
    timeout: float = 5.0,
) -> Tuple[bool, str, List[str]]:
    base = base_url.rstrip("/")
    try:
        r = requests.get(f"{base}/api/tags", timeout=timeout)
        r.raise_for_status()
        data = r.json()
        names = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
    except requests.exceptions.ConnectionError:
        return False, "Cannot connect. Start Ollama Desktop or run: ollama serve", []
    except Exception as exc:
        return False, str(exc), []

    resolved = resolve_ollama_model(model, names) if model else model

    if model:
        if resolved not in names and not any(
            n == model or n.startswith(model.split(":")[0] + ":") for n in names
        ):
            return (
                False,
                f"Model '{model}' not found. Run: ollama pull {model.split(':')[0]}",
                names,
            )
        probe = _probe_inference(base, resolved, timeout=min(timeout, 30.0))
        if not probe[0]:
            return False, probe[1], names
        return True, f"Ollama OK · model {resolved} · {probe[1]}", names

    return True, f"Ollama OK ({len(names)} model(s) available)", names


def _probe_inference(base: str, model: str, timeout: float = 20.0) -> Tuple[bool, str]:
    try:
        r = requests.post(
            f"{base}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": "Reply with: []"}],
                "stream": False,
            },
            timeout=timeout,
        )
        if r.status_code == 404:
            r = requests.post(
                f"{base}/api/generate",
                json={"model": model, "prompt": "Reply with: []", "stream": False},
                timeout=timeout,
            )
        if r.status_code == 404:
            return False, f"model '{model}' not found (404). Use a name from: ollama list"
        r.raise_for_status()
        return True, "chat/generate OK"
    except requests.exceptions.ConnectionError:
        return False, "cannot connect for inference test"
    except Exception as exc:
        return False, str(exc)


def ollama_chat(
    prompt: str,
    *,
    system: str = "",
    model: str = "llama3.2",
    base_url: str = "http://localhost:11434",
    temperature: float = 0.3,
    timeout: float = 120.0,
) -> str:
    base = base_url.rstrip("/")
    try:
        tags = requests.get(f"{base}/api/tags", timeout=min(timeout, 15.0))
        tags.raise_for_status()
        names = [m.get("name", "") for m in tags.json().get("models", []) if m.get("name")]
        model = resolve_ollama_model(model, names)
    except Exception as exc:
        logger.warning("Could not resolve Ollama model name: %s", exc)

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    chat_body = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature},
    }
    try:
        r = requests.post(f"{base}/api/chat", json=chat_body, timeout=timeout)
        if r.status_code == 404:
            body = r.text[:200]
            if "model" in body.lower() or "not found" in body.lower():
                raise ValueError(
                    f"Ollama model '{model}' not found. Run: ollama list  then  ollama pull {model.split(':')[0]}"
                )
            combined = (system + "\n\n" + prompt).strip() if system else prompt
            r = requests.post(
                f"{base}/api/generate",
                json={
                    "model": model,
                    "prompt": combined,
                    "stream": False,
                    "options": {"temperature": temperature},
                },
                timeout=timeout,
            )
        if r.status_code == 404:
            raise ValueError(
                f"Ollama API not found at {base}/api/chat. Update Ollama or check ollama_url in config."
            )
        r.raise_for_status()
        data = r.json()
        if "message" in data and isinstance(data["message"], dict):
            return str(data["message"].get("content", ""))
        if "response" in data:
            return str(data["response"])
        return str(data)
    except requests.exceptions.ConnectionError as exc:
        raise ConnectionError(
            "Cannot reach Ollama. Start Ollama Desktop or run: ollama serve"
        ) from exc
