"""
scanner/ai_analyzer.py — AI mode: one-at-a-time directory analysis with stop support
"""

import threading
import requests as req
from typing import List, Dict, Callable


class AIAnalyzer:
    def __init__(self, base_url, api_key, model=None, proxies=None, callback=None, timeout=30):
        self.base_url = base_url.rstrip("/")
        self.api_key  = api_key
        self.model    = model
        self.proxies  = proxies or {}
        self.callback = callback
        self.timeout  = timeout
        self._stop_event = threading.Event()
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

    # ── Stop ──────────────────────────────────────────────────────────────────
    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()

    # ── Emit ──────────────────────────────────────────────────────────────────
    def _emit(self, event, data):
        if self.callback:
            self.callback(event, data)

    # ── List models ───────────────────────────────────────────────────────────
    def list_models(self) -> List[str]:
        for endpoint in ["/v1/models", "/models", "/api/v1/models"]:
            try:
                r = req.get(f"{self.base_url}{endpoint}", headers=self._headers,
                            proxies=self.proxies, timeout=10, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    if "data"   in data: return [m.get("id", str(m)) for m in data["data"]]
                    if "models" in data: return [m.get("id", str(m)) for m in data["models"]]
                    if isinstance(data, list): return [m.get("id", str(m)) for m in data]
            except Exception:
                continue
        return ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229",
                "claude-3-haiku-20240307", "gpt-4o", "cisai-pro"]

    # ── LLM call ─────────────────────────────────────────────────────────────
    def _call_llm(self, prompt: str) -> str:
        payload = {"model": self.model, "max_tokens": 256,
                   "messages": [{"role": "user", "content": prompt}]}
        # Try Anthropic /v1/messages
        for endpoint in ["/v1/messages", "/messages"]:
            try:
                r = req.post(f"{self.base_url}{endpoint}", headers=self._headers,
                             json=payload, proxies=self.proxies, timeout=self.timeout, verify=False)
                if r.status_code == 200:
                    d = r.json()
                    if "content" in d and isinstance(d["content"], list):
                        return d["content"][0].get("text", "")
                    if "choices" in d:
                        return d["choices"][0]["message"]["content"]
            except Exception:
                continue
        # Try OpenAI chat completions
        try:
            r = req.post(f"{self.base_url}/v1/chat/completions", headers=self._headers,
                         json=payload, proxies=self.proxies, timeout=self.timeout, verify=False)
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"[LLM Error] {e}"
        return "[LLM Error] No response from model."

    # ── Analyze ONE directory ─────────────────────────────────────────────────
    def _analyze_single(self, dir_data: Dict) -> Dict:
        url   = dir_data.get("url", "")
        files = dir_data.get("files", [])
        lines = [f"  {'[DIR]' if f.get('is_dir') else '[FILE]'} {f['name']}"
                 for f in files[:25]]
        listing = "\n".join(lines) if lines else "  (no file listing)"

        prompt = (
            f"You are doing a VAPT security audit.\n\n"
            f"This web directory is publicly accessible:\n"
            f"URL: {url}\n"
            f"Contents ({len(files)} items):\n{listing}\n\n"
            f"Reply in exactly ONE line:\n"
            f"SENSITIVE: <1-sentence reason>   — if it likely contains PII, identity documents,\n"
            f"credentials, financial data, medical records, security reports, employee data, CCTV info.\n"
            f"NOT_SENSITIVE: <1-sentence reason>   — if it is public/non-sensitive content."
        )
        response = self._call_llm(prompt).strip()
        is_sensitive = response.upper().startswith("SENSITIVE:")
        return {"url": url, "file_count": len(files),
                "is_sensitive": is_sensitive, "ai_verdict": response}

    # ── Sequential analysis (one dir at a time) ───────────────────────────────
    def analyze_sequential(self, dirs: List[Dict]) -> None:
        self._stop_event.clear()
        total = len(dirs)
        if total == 0:
            self._emit("ai_complete", {"msg": "No directories to analyze.", "total": 0, "sensitive": 0})
            return

        self._emit("ai_start", {"msg": f"Analyzing {total} director{'y' if total==1 else 'ies'} one by one...",
                                "total": total})
        sensitive_count = 0
        for i, d in enumerate(dirs):
            if self._stop_event.is_set():
                self._emit("ai_stopped", {"msg": f"AI stopped after {i}/{total} directories."})
                return
            self._emit("ai_dir_start", {"url": d.get("url",""), "current": i+1, "total": total})
            result = self._analyze_single(d)
            if result["is_sensitive"]:
                sensitive_count += 1
            self._emit("ai_dir_result", {**result, "current": i+1, "total": total})

        self._emit("ai_complete", {
            "msg": f"AI done. {sensitive_count}/{total} flagged sensitive.",
            "total": total, "sensitive": sensitive_count
        })
