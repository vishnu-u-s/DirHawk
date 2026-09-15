"""
scanner/core.py — Core directory listing scanner engine for DirHawk
"""

import os
import re
import time
import json
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Dict, Optional

import requests
from bs4 import BeautifulSoup

from .proxy import ProxyConfig


# ─── Signatures that indicate directory listing is enabled ──────────────────
DIR_LISTING_SIGNATURES = [
    "index of /",
    "directory listing for",
    "[parentdir]",
    "<title>index of",
    "directory index",
    "last modified</a>",
    "apache server at",
    "nginx directory listing",
]

SENSITIVE_KEYWORDS = [
    "aadhaar", "aadhar", "pan", "passport", "visa",
    "bank", "account", "ifsc", "gst", "obc", "caste",
    "salary", "payroll", "invoice", "audit", "security",
    "certificate", "signature", "consent", "medical",
    "employee", "staff", "personnel", "private", "secret",
    "credential", "password", "config", "backup", "dump",
    "sslc", "marksheet", "grade", "identity", "kyc",
    "cctv", "camera", "infrastructure", "financial",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DirHawk/1.0; Security Scanner)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}


# ─── Result data model ───────────────────────────────────────────────────────
class ScanResult:
    def __init__(self, target: str):
        self.target = target
        self.domain = urlparse(target).netloc or target
        self.started_at = datetime.now().isoformat()
        self.finished_at = None
        self.open_dirs: List[Dict] = []
        self.sensitive_dirs: List[Dict] = []
        self.total_checked = 0
        self.errors: List[str] = []
        self._seen_urls: set = set()  # dedup tracker
        self.found_403: List[str] = []  # directories that exist but are forbidden

    def is_seen(self, url: str) -> bool:
        """Return True if this URL was already reported."""
        normalized = url.rstrip("/") + "/"
        return normalized in self._seen_urls

    def mark_seen(self, url: str):
        self._seen_urls.add(url.rstrip("/") + "/")

    def add_open_dir(self, url: str, files: list, is_sensitive: bool, reason: str = ""):
        entry = {
            "url": url,
            "files": files,
            "is_sensitive": is_sensitive,
            "sensitive_reason": reason,
            "found_at": datetime.now().isoformat(),
        }
        self.open_dirs.append(entry)
        if is_sensitive:
            self.sensitive_dirs.append(entry)

    def finalize(self):
        self.finished_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "domain": self.domain,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": {
                "total_checked": self.total_checked,
                "open_dirs_found": len(self.open_dirs),
                "sensitive_dirs_found": len(self.sensitive_dirs),
            },
            "open_dirs": self.open_dirs,
            "sensitive_dirs": self.sensitive_dirs,
            "found_403": self.found_403,
            "errors": self.errors,
        }


# ─── Core Scanner ─────────────────────────────────────────────────────────────
class DirectoryScanner:
    def __init__(
        self,
        proxy_config: ProxyConfig = None,
        timeout: int = 10,
        max_workers: int = 10,
        max_depth: int = 3,
        wordlist_path: str = None,
        callback: Callable = None,
        results_dir: str = "results",
    ):
        self.proxy = proxy_config or ProxyConfig()
        self.timeout = timeout
        self.max_workers = max_workers
        self.max_depth = max_depth
        self.callback = callback  # fn(event: str, data: dict)
        self.results_dir = results_dir
        self._stop_event = threading.Event()

        self.wordlist = self._load_wordlist(wordlist_path)

        os.makedirs(self.results_dir, exist_ok=True)

    # ── Wordlist ──────────────────────────────────────────────────────────────
    def _load_wordlist(self, path: str) -> List[str]:
        default = os.path.join(
            os.path.dirname(__file__), "..", "wordlists", "common_dirs.txt"
        )
        target = path or default
        try:
            with open(target, "r") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            return ["uploads", "admin", "backup", "files", "data", "docs", "images"]

    # ── HTTP ──────────────────────────────────────────────────────────────────
    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            r = requests.get(
                url,
                headers=HEADERS,
                proxies=self.proxy.get_proxies(),
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
            return r
        except Exception as e:
            return None

    # ── Detection ─────────────────────────────────────────────────────────────
    def _is_dir_listing(self, response: requests.Response) -> bool:
        if response is None or response.status_code not in (200,):
            return False
        text_lower = response.text.lower()
        return any(sig in text_lower for sig in DIR_LISTING_SIGNATURES)

    # ── Parse listed files/dirs ───────────────────────────────────────────────
    def _parse_listing(self, html: str, base_url: str) -> List[Dict]:
        soup = BeautifulSoup(html, "html.parser")
        entries = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href in ("../", "/", "./") or href.startswith("?") or href.startswith("http"):
                continue
            full_url = urljoin(base_url, href)
            name = a.get_text(strip=True) or href
            entries.append({
                "name": name,
                "url": full_url,
                "is_dir": href.endswith("/"),
            })
        return entries

    # ── Sensitivity check ─────────────────────────────────────────────────────
    def _check_sensitivity(self, url: str, files: list) -> tuple:
        text = (url + " " + " ".join(f["name"] for f in files)).lower()
        hits = [kw for kw in SENSITIVE_KEYWORDS if kw in text]
        is_sensitive = bool(hits)
        reason = f"Keywords: {', '.join(hits)}" if hits else ""
        return is_sensitive, reason

    # ── Emit event ────────────────────────────────────────────────────────────
    def _emit(self, event: str, data: dict):
        if self.callback:
            self.callback(event, data)

    # ── Scan single URL ───────────────────────────────────────────────────────
    def _scan_url(self, url: str, result: ScanResult, depth: int = 0):
        if self._stop_event.is_set() or depth > self.max_depth:
            return

        url = url.rstrip("/") + "/"
        self._emit("progress", {"msg": f"Checking: {url}", "url": url})

        resp = self._get(url)
        result.total_checked += 1

        if resp is None:
            return

        # 403 = exists but forbidden
        if resp.status_code == 403:
            if not result.is_seen(url):
                result.mark_seen(url)
                result.found_403.append(url)
                self._emit("forbidden", {"url": url, "status": 403})
            return

        if self._is_dir_listing(resp):
            # ── Dedup check ──────────────────────────────────────────────────
            if result.is_seen(url):
                return
            result.mark_seen(url)
            # ────────────────────────────────────────────────────────────────

            files = self._parse_listing(resp.text, url)
            is_sensitive, reason = self._check_sensitivity(url, files)

            result.add_open_dir(url, files, is_sensitive, reason)
            self._emit("found", {
                "url": url,
                "file_count": len(files),
                "is_sensitive": is_sensitive,
                "reason": reason,
                "files": files[:20],  # preview
            })

            # Recurse into sub-directories
            if depth < self.max_depth:
                sub_dirs = [f["url"] for f in files if f["is_dir"]]
                for sub in sub_dirs:
                    if self._stop_event.is_set():
                        break
                    self._scan_url(sub, result, depth + 1)

    # ── Wordlist probe ────────────────────────────────────────────────────────
    def _probe_wordlist(self, base_url: str, result: ScanResult):
        base = base_url.rstrip("/")

        def probe_one(word: str):
            if self._stop_event.is_set():
                return
            url = f"{base}/{word}/"
            resp = self._get(url)
            result.total_checked += 1
            if resp and resp.status_code == 403:
                if not result.is_seen(url):
                    result.mark_seen(url)
                    result.found_403.append(url)
                    self._emit("forbidden", {"url": url, "status": 403})
            elif resp and self._is_dir_listing(resp):
                # ── Dedup check ──────────────────────────────────────────────
                if result.is_seen(url):
                    return
                result.mark_seen(url)
                # ────────────────────────────────────────────────────────────

                files = self._parse_listing(resp.text, url)
                is_sensitive, reason = self._check_sensitivity(url, files)
                result.add_open_dir(url, files, is_sensitive, reason)
                self._emit("found", {
                    "url": url,
                    "file_count": len(files),
                    "is_sensitive": is_sensitive,
                    "reason": reason,
                    "files": files[:20],
                })
                # Recurse
                sub_dirs = [f["url"] for f in files if f["is_dir"]]
                for sub in sub_dirs:
                    if not self._stop_event.is_set():
                        self._scan_url(sub, result, depth=1)
            self._emit("progress", {"msg": f"[{result.total_checked}] {url} → {resp.status_code if resp else 'ERR'}"})

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(probe_one, w): w for w in self.wordlist}
            for f in as_completed(futures):
                if self._stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    f.result()
                except Exception as e:
                    result.errors.append(str(e))

    # ── Public: scan one target ───────────────────────────────────────────────
    def scan(self, target: str) -> ScanResult:
        self._stop_event.clear()

        # Normalize URL
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        result = ScanResult(target)
        self._emit("start", {"target": target, "proxy": str(self.proxy)})

        # 1. Check base URL
        self._scan_url(target, result, depth=0)

        # 2. Wordlist probe
        self._emit("progress", {"msg": "Starting wordlist enumeration..."})
        self._probe_wordlist(target, result)

        result.finalize()
        self._save_result(result)
        self._emit("done", result.to_dict())
        return result

    # ── Public: scan bulk targets ─────────────────────────────────────────────
    def scan_bulk(self, targets: List[str]) -> List[ScanResult]:
        results = []
        for i, target in enumerate(targets):
            if self._stop_event.is_set():
                break
            self._emit("bulk_progress", {
                "current": i + 1,
                "total": len(targets),
                "target": target,
            })
            r = self.scan(target)
            results.append(r)
        return results

    def stop(self):
        self._stop_event.set()
        self._emit("stopped", {"msg": "Scan stopped by user."})

    # ── Save result ───────────────────────────────────────────────────────────
    def _save_result(self, result: ScanResult):
        safe_name = re.sub(r"[^\w\-.]", "_", result.domain)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{safe_name}_{ts}.json"
        path = os.path.join(self.results_dir, filename)
        with open(path, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        self._emit("saved", {"path": path, "domain": result.domain})
        return path
