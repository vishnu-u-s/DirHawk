"""
scanner/proxy.py — Proxy configuration helper for DirHawk
"""

import socket
import requests
from urllib.parse import urlparse


class ProxyConfig:
    """
    Handles proxy configuration for requests.
    Supports SOCKS5, SOCKS4, HTTP proxies.
    """

    def __init__(self, proxy_str: str = None):
        self.proxy_str = proxy_str.strip() if proxy_str else None
        self.proxies   = self._build_proxies()

    def _build_proxies(self) -> dict:
        if not self.proxy_str:
            return {}
        return {"http": self.proxy_str, "https": self.proxy_str}

    def get_proxies(self) -> dict:
        return self.proxies

    def is_active(self) -> bool:
        return bool(self.proxy_str)

    def __repr__(self):
        return f"<ProxyConfig proxy={self.proxy_str}>" if self.is_active() else "<ProxyConfig direct>"

    @staticmethod
    def test_proxy(proxy_str: str, timeout: int = 6) -> tuple:
        """
        Test if a proxy is reachable.
        Step 1 — TCP socket: is the proxy port open?
        Step 2 — HTTP through proxy: does routing work?
        Returns (success: bool, message: str)
        """
        parsed = urlparse(proxy_str)
        host = parsed.hostname
        port = parsed.port or 1080

        # ── Step 1: TCP connectivity ──────────────────────────────────────────
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
        except Exception as e:
            return False, f"Cannot reach {host}:{port} — {e}"

        # ── Step 2: HTTP routing through proxy ────────────────────────────────
        proxies = {"http": proxy_str, "https": proxy_str}
        test_urls = [
            "http://httpbin.org/ip",
            "http://example.com",
            "http://www.google.com",
            "http://detectportal.firefox.com/success.txt",
        ]
        for url in test_urls:
            try:
                r = requests.get(url, proxies=proxies, timeout=timeout,
                                 verify=False, allow_redirects=True)
                if r.status_code < 500:
                    return True, (
                        f"Proxy {host}:{port} is active — "
                        f"routing OK via {url.split('/')[2]} (HTTP {r.status_code})"
                    )
            except Exception:
                continue

        # TCP open but no external routing — internal-only proxy (still valid)
        return True, (
            f"Proxy {host}:{port} port is OPEN. "
            f"External HTTP routing unavailable — may be an internal-only proxy (still usable for scanning)"
        )
