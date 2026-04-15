"""LLM integration — supports Ollama and LM Studio (OpenAI-compatible)."""
import logging
import httpx
from typing import Any

logger = logging.getLogger(__name__)


def _build_prompt(device: dict) -> str:
    ports = ", ".join(
        f"{p['port']}/{p['protocol']} ({p.get('service') or 'unknown'})"
        for p in (device.get("ports") or [])
    ) or "none discovered"

    reasons = "\n".join(
        f"  - {r['rule']}: {r['explanation']} (+{r['delta']:.1f})"
        for r in (device.get("score_reasons") or [])
    ) or "  - none (score is 0)"

    return f"""You are a network security analyst reviewing a home network device.

Device:
  IP:       {device.get('ip', 'unknown')}
  Hostname: {device.get('hostname') or 'unknown'}
  MAC:      {device.get('mac') or 'unknown'}
  Vendor:   {device.get('vendor') or 'unknown'}
  Category: {device.get('category', 'unknown')}
  Score:    {device.get('suspicion_score', 0):.1f} / 100
  Open ports: {ports}

Triggered rules:
{reasons}

Provide a concise security assessment in three short sections:
1. SUMMARY: What this device appears to be doing (1-2 sentences).
2. RISK: Why it is or isn't concerning (1-2 sentences).
3. ACTION: One specific recommended action the homeowner should take.

Be direct and non-technical. Do not repeat the raw numbers."""


def _call_ollama(base_url: str, model: str, prompt: str, timeout: float) -> str:
    url = base_url.rstrip("/") + "/api/generate"
    payload = {"model": model, "prompt": prompt, "stream": False}
    with httpx.Client(timeout=timeout) as client:
        r = client.post(url, json=payload)
        r.raise_for_status()
        return r.json()["response"].strip()


def _call_lmstudio(base_url: str, model: str, prompt: str, timeout: float) -> str:
    url = base_url.rstrip("/") + "/v1/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    with httpx.Client(timeout=timeout) as client:
        r = client.post(url, json=payload)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()


def analyze_device(device: dict, provider: str, base_url: str, model: str, timeout: float = 60.0) -> dict[str, Any]:
    """Call the configured LLM and return a structured analysis."""
    prompt = _build_prompt(device)
    try:
        if provider == "lmstudio":
            text = _call_lmstudio(base_url, model, prompt, timeout)
        else:
            text = _call_ollama(base_url, model, prompt, timeout)
        return {"ok": True, "analysis": text, "model": model, "provider": provider}
    except httpx.ConnectError:
        msg = f"Cannot connect to {provider} at {base_url}. Is it running?"
        logger.warning(msg)
        return {"ok": False, "error": msg}
    except httpx.HTTPStatusError as e:
        msg = f"{provider} returned HTTP {e.response.status_code}: {e.response.text[:200]}"
        logger.warning(msg)
        return {"ok": False, "error": msg}
    except Exception as e:
        logger.exception("LLM analysis failed")
        return {"ok": False, "error": str(e)}
