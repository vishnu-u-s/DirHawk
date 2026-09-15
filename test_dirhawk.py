"""
test_dirhawk.py — Unit & integration tests for DirHawk
Tests the scanner package: core logic, proxy config, sensitivity detection,
result model, wordlist loading, and URL parsing.

Run with:
    python -m pytest test_dirhawk.py -v
  or:
    python test_dirhawk.py
"""

import os
import sys
import json
import threading
import unittest
from unittest.mock import MagicMock, patch, mock_open
from datetime import datetime

# Make sure the project root is on the path
sys.path.insert(0, os.path.dirname(__file__))

from scanner.core import (
    DirectoryScanner,
    ScanResult,
    DIR_LISTING_SIGNATURES,
    SENSITIVE_KEYWORDS,
    HEADERS,
)
from scanner.proxy import ProxyConfig


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _fake_response(status_code: int = 200, text: str = "") -> MagicMock:
    """Build a minimal mock requests.Response."""
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    return r


def _dir_listing_html(title="Index of /uploads", items=None):
    """Generate minimal Apache-style directory listing HTML."""
    items = items or [
        '<a href="file1.txt">file1.txt</a>',
        '<a href="subdir/">subdir/</a>',
    ]
    body = "\n".join(f"<li>{i}</li>" for i in items)
    return f"""
    <html>
      <head><title>{title}</title></head>
      <body>
        <h1>{title}</h1>
        <ul>{body}</ul>
      </body>
    </html>
    """


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ProxyConfig tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestProxyConfig(unittest.TestCase):

    def test_no_proxy(self):
        """ProxyConfig with no args should be inactive and return empty dict."""
        pc = ProxyConfig()
        self.assertFalse(pc.is_active())
        self.assertEqual(pc.get_proxies(), {})

    def test_none_proxy(self):
        pc = ProxyConfig(None)
        self.assertFalse(pc.is_active())

    def test_socks5_proxy(self):
        pc = ProxyConfig("socks5://127.0.0.1:9050")
        self.assertTrue(pc.is_active())
        proxies = pc.get_proxies()
        self.assertEqual(proxies["http"], "socks5://127.0.0.1:9050")
        self.assertEqual(proxies["https"], "socks5://127.0.0.1:9050")

    def test_http_proxy(self):
        pc = ProxyConfig("http://proxy.example.com:8080")
        self.assertTrue(pc.is_active())
        self.assertIn("http", pc.get_proxies())

    def test_repr_active(self):
        pc = ProxyConfig("socks5://127.0.0.1:9050")
        self.assertIn("socks5", repr(pc))

    def test_repr_direct(self):
        pc = ProxyConfig()
        self.assertIn("direct", repr(pc))

    def test_whitespace_stripped(self):
        pc = ProxyConfig("  socks5://127.0.0.1:9050  ")
        self.assertEqual(pc.proxy_str, "socks5://127.0.0.1:9050")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ScanResult model tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanResult(unittest.TestCase):

    def setUp(self):
        self.result = ScanResult("http://example.com")

    def test_initial_state(self):
        r = self.result
        self.assertEqual(r.target, "http://example.com")
        self.assertEqual(r.domain, "example.com")
        self.assertEqual(r.open_dirs, [])
        self.assertEqual(r.sensitive_dirs, [])
        self.assertEqual(r.total_checked, 0)
        self.assertEqual(r.errors, [])

    def test_add_open_dir_non_sensitive(self):
        self.result.add_open_dir("http://example.com/images/", [], False, "")
        self.assertEqual(len(self.result.open_dirs), 1)
        self.assertEqual(len(self.result.sensitive_dirs), 0)

    def test_add_open_dir_sensitive(self):
        self.result.add_open_dir("http://example.com/backup/", [], True, "Keywords: backup")
        self.assertEqual(len(self.result.open_dirs), 1)
        self.assertEqual(len(self.result.sensitive_dirs), 1)
        self.assertEqual(self.result.sensitive_dirs[0]["sensitive_reason"], "Keywords: backup")

    def test_dedup_is_seen(self):
        url = "http://example.com/docs/"
        self.assertFalse(self.result.is_seen(url))
        self.result.mark_seen(url)
        self.assertTrue(self.result.is_seen(url))

    def test_dedup_trailing_slash_normalization(self):
        """URLs with and without trailing slash should be treated the same."""
        self.result.mark_seen("http://example.com/docs")
        self.assertTrue(self.result.is_seen("http://example.com/docs/"))

    def test_finalize_sets_timestamp(self):
        self.assertIsNone(self.result.finished_at)
        self.result.finalize()
        self.assertIsNotNone(self.result.finished_at)

    def test_to_dict_structure(self):
        self.result.finalize()
        d = self.result.to_dict()
        expected_keys = {"target", "domain", "started_at", "finished_at",
                         "summary", "open_dirs", "sensitive_dirs", "found_403", "errors"}
        self.assertTrue(expected_keys.issubset(d.keys()))

    def test_to_dict_summary_counts(self):
        self.result.add_open_dir("http://example.com/a/", [], False, "")
        self.result.add_open_dir("http://example.com/b/", [], True, "Keywords: backup")
        self.result.total_checked = 20
        self.result.finalize()
        summary = self.result.to_dict()["summary"]
        self.assertEqual(summary["total_checked"], 20)
        self.assertEqual(summary["open_dirs_found"], 2)
        self.assertEqual(summary["sensitive_dirs_found"], 1)

    def test_found_403_list(self):
        self.result.found_403.append("http://example.com/admin/")
        d = self.result.to_dict()
        self.assertIn("http://example.com/admin/", d["found_403"])


# ═══════════════════════════════════════════════════════════════════════════════
# 3. DirectoryScanner — sensitivity detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestSensitivityCheck(unittest.TestCase):

    def setUp(self):
        self.scanner = DirectoryScanner(results_dir="results")

    def _files(self, names):
        return [{"name": n, "url": f"http://x/{n}", "is_dir": False} for n in names]

    def test_sensitive_keyword_in_url(self):
        is_s, reason = self.scanner._check_sensitivity(
            "http://example.com/backup/", []
        )
        self.assertTrue(is_s)
        self.assertIn("backup", reason.lower())

    def test_sensitive_keyword_in_filename(self):
        is_s, reason = self.scanner._check_sensitivity(
            "http://example.com/data/",
            self._files(["aadhaar_list.csv", "photo.jpg"])
        )
        self.assertTrue(is_s)
        self.assertIn("aadhaar", reason.lower())

    def test_not_sensitive(self):
        is_s, reason = self.scanner._check_sensitivity(
            "http://example.com/images/",
            self._files(["logo.png", "banner.jpg"])
        )
        self.assertFalse(is_s)
        self.assertEqual(reason, "")

    def test_multiple_keywords_reported(self):
        is_s, reason = self.scanner._check_sensitivity(
            "http://example.com/hr/",
            self._files(["salary_jan.xlsx", "employee_data.csv"])
        )
        self.assertTrue(is_s)
        # Both keywords should be in reason
        self.assertIn("salary", reason.lower())
        self.assertIn("employee", reason.lower())

    def test_all_sensitive_keywords_recognized(self):
        """Spot-check that SENSITIVE_KEYWORDS are actually used."""
        for kw in ["password", "credential", "medical", "kyc", "cctv"]:
            is_s, _ = self.scanner._check_sensitivity(
                f"http://example.com/{kw}/", []
            )
            self.assertTrue(is_s, f"Keyword '{kw}' not detected as sensitive")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. DirectoryScanner — directory listing detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestDirListingDetection(unittest.TestCase):

    def setUp(self):
        self.scanner = DirectoryScanner(results_dir="results")

    def test_detects_index_of(self):
        resp = _fake_response(200, "<html><title>Index of /uploads</title></html>")
        self.assertTrue(self.scanner._is_dir_listing(resp))

    def test_detects_directory_listing_for(self):
        resp = _fake_response(200, "Directory listing for /data")
        self.assertTrue(self.scanner._is_dir_listing(resp))

    def test_detects_parentdir(self):
        resp = _fake_response(200, "<a href='/'>[ParentDir]</a> Last modified</a>")
        self.assertTrue(self.scanner._is_dir_listing(resp))

    def test_normal_page_not_detected(self):
        resp = _fake_response(200, "<html><body><h1>Welcome</h1></body></html>")
        self.assertFalse(self.scanner._is_dir_listing(resp))

    def test_404_not_detected(self):
        resp = _fake_response(404, "Index of /secret")
        self.assertFalse(self.scanner._is_dir_listing(resp))

    def test_none_response_not_detected(self):
        self.assertFalse(self.scanner._is_dir_listing(None))

    def test_all_signatures_detected(self):
        """Every entry in DIR_LISTING_SIGNATURES should trigger detection."""
        for sig in DIR_LISTING_SIGNATURES:
            resp = _fake_response(200, sig)
            self.assertTrue(
                self.scanner._is_dir_listing(resp),
                f"Signature not detected: '{sig}'"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. DirectoryScanner — HTML listing parser
# ═══════════════════════════════════════════════════════════════════════════════

class TestParseListingHTML(unittest.TestCase):

    def setUp(self):
        self.scanner = DirectoryScanner(results_dir="results")

    def test_parses_files(self):
        html = _dir_listing_html(items=['<a href="report.pdf">report.pdf</a>'])
        entries = self.scanner._parse_listing(html, "http://example.com/docs/")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "report.pdf")
        self.assertFalse(entries[0]["is_dir"])

    def test_parses_subdirs(self):
        html = _dir_listing_html(items=['<a href="subdir/">subdir/</a>'])
        entries = self.scanner._parse_listing(html, "http://example.com/data/")
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["is_dir"])

    def test_skips_parent_dir_link(self):
        html = _dir_listing_html(items=[
            '<a href="../">Parent</a>',
            '<a href="/">Root</a>',
            '<a href="./"></a>',
            '<a href="file.txt">file.txt</a>',
        ])
        entries = self.scanner._parse_listing(html, "http://example.com/docs/")
        # Only file.txt should survive
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "file.txt")

    def test_skips_query_links(self):
        html = _dir_listing_html(items=['<a href="?C=N&O=D">Name</a>'])
        entries = self.scanner._parse_listing(html, "http://example.com/")
        self.assertEqual(len(entries), 0)

    def test_full_url_built_correctly(self):
        html = _dir_listing_html(items=['<a href="photo.jpg">photo.jpg</a>'])
        entries = self.scanner._parse_listing(html, "http://example.com/gallery/")
        self.assertEqual(entries[0]["url"], "http://example.com/gallery/photo.jpg")

    def test_empty_listing(self):
        entries = self.scanner._parse_listing("<html><body></body></html>", "http://example.com/")
        self.assertEqual(entries, [])


# ═══════════════════════════════════════════════════════════════════════════════
# 6. DirectoryScanner — wordlist loading
# ═══════════════════════════════════════════════════════════════════════════════

class TestWordlistLoading(unittest.TestCase):

    def test_loads_default_wordlist(self):
        """Default wordlist file in wordlists/ should be loadable."""
        scanner = DirectoryScanner(results_dir="results")
        self.assertIsInstance(scanner.wordlist, list)
        self.assertGreater(len(scanner.wordlist), 0)

    def test_loads_custom_wordlist(self):
        custom_content = "alpha\nbeta\n#comment\ngamma\n"
        with patch("builtins.open", mock_open(read_data=custom_content)):
            scanner = DirectoryScanner(
                wordlist_path="/fake/custom.txt",
                results_dir="results"
            )
        # comments and blank lines excluded
        self.assertIn("alpha", scanner.wordlist)
        self.assertIn("gamma", scanner.wordlist)
        self.assertNotIn("#comment", scanner.wordlist)

    def test_fallback_wordlist_on_missing_file(self):
        """If both custom and default wordlists are missing, use hardcoded fallback."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            scanner = DirectoryScanner(
                wordlist_path="/nonexistent/path.txt",
                results_dir="results"
            )
        self.assertIn("admin", scanner.wordlist)
        self.assertIn("backup", scanner.wordlist)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. DirectoryScanner — scan URL logic (mocked HTTP)
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanUrlLogic(unittest.TestCase):

    def _make_scanner(self, callback=None):
        return DirectoryScanner(
            results_dir="results",
            max_depth=1,
            callback=callback,
        )

    def test_scan_url_records_open_dir(self):
        events = []
        scanner = self._make_scanner(callback=lambda e, d: events.append((e, d)))

        html = _dir_listing_html(items=['<a href="data.csv">data.csv</a>'])
        with patch.object(scanner, "_get", return_value=_fake_response(200, html)):
            result = ScanResult("http://example.com")
            scanner._scan_url("http://example.com/uploads/", result, depth=0)

        self.assertEqual(len(result.open_dirs), 1)
        self.assertEqual(result.total_checked, 1)
        found_events = [e for e, _ in events if e == "found"]
        self.assertEqual(len(found_events), 1)

    def test_scan_url_skips_404(self):
        scanner = self._make_scanner()
        with patch.object(scanner, "_get", return_value=_fake_response(404, "")):
            result = ScanResult("http://example.com")
            scanner._scan_url("http://example.com/missing/", result, depth=0)

        self.assertEqual(len(result.open_dirs), 0)

    def test_scan_url_records_403_as_forbidden(self):
        scanner = self._make_scanner()
        with patch.object(scanner, "_get", return_value=_fake_response(403, "")):
            result = ScanResult("http://example.com")
            scanner._scan_url("http://example.com/admin/", result, depth=0)

        self.assertIn("http://example.com/admin/", result.found_403)

    def test_scan_url_dedup_prevents_double_entry(self):
        """Same URL scanned twice should only appear once in open_dirs."""
        scanner = self._make_scanner()
        # Use a listing with NO sub-directories so recursion doesn't add extra entries
        html = _dir_listing_html(items=['<a href="file1.txt">file1.txt</a>'])
        result = ScanResult("http://example.com")

        with patch.object(scanner, "_get", return_value=_fake_response(200, html)):
            scanner._scan_url("http://example.com/uploads/", result, depth=0)
            scanner._scan_url("http://example.com/uploads/", result, depth=0)

        self.assertEqual(len(result.open_dirs), 1)

    def test_scan_url_respects_max_depth(self):
        """At max_depth, recursion should stop."""
        scanner = self._make_scanner()
        scanner.max_depth = 0  # no recursion at all

        html = _dir_listing_html(items=['<a href="subdir/">subdir/</a>'])
        call_count = 0

        original_get = scanner._get
        def counting_get(url):
            nonlocal call_count
            call_count += 1
            return _fake_response(200, html)

        with patch.object(scanner, "_get", side_effect=counting_get):
            result = ScanResult("http://example.com")
            scanner._scan_url("http://example.com/files/", result, depth=0)

        # At depth=0, max_depth=0 → found the dir but should NOT recurse into subdir
        self.assertEqual(call_count, 1)

    def test_scan_url_none_response(self):
        """None response (network error) should not crash, just increment counter."""
        scanner = self._make_scanner()
        with patch.object(scanner, "_get", return_value=None):
            result = ScanResult("http://example.com")
            scanner._scan_url("http://example.com/error/", result, depth=0)

        self.assertEqual(result.total_checked, 1)
        self.assertEqual(len(result.open_dirs), 0)

    def test_stop_event_halts_scan(self):
        scanner = self._make_scanner()
        scanner._stop_event.set()  # pre-stop

        with patch.object(scanner, "_get") as mock_get:
            result = ScanResult("http://example.com")
            scanner._scan_url("http://example.com/files/", result, depth=0)
            mock_get.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# 8. DirectoryScanner — callback events
# ═══════════════════════════════════════════════════════════════════════════════

class TestCallbackEvents(unittest.TestCase):

    def test_no_callback_does_not_crash(self):
        """Scanner without a callback should work silently."""
        scanner = DirectoryScanner(results_dir="results", callback=None)
        # Use a listing with only files (no sub-dirs) to avoid recursion side effects
        html = _dir_listing_html(items=['<a href="data.csv">data.csv</a>'])
        with patch.object(scanner, "_get", return_value=_fake_response(200, html)):
            result = ScanResult("http://example.com")
            scanner._scan_url("http://example.com/data/", result, depth=0)

        self.assertEqual(len(result.open_dirs), 1)

    def test_found_event_data_shape(self):
        received = {}

        def cb(event, data):
            if event == "found":
                received.update(data)

        scanner = DirectoryScanner(results_dir="results", callback=cb)
        html = _dir_listing_html()
        with patch.object(scanner, "_get", return_value=_fake_response(200, html)):
            result = ScanResult("http://example.com")
            scanner._scan_url("http://example.com/docs/", result, depth=0)

        required_fields = {"url", "file_count", "is_sensitive", "reason"}
        self.assertTrue(required_fields.issubset(received.keys()),
                        f"Missing fields: {required_fields - received.keys()}")

    def test_forbidden_event_emitted_on_403(self):
        events = []
        scanner = DirectoryScanner(
            results_dir="results",
            callback=lambda e, d: events.append(e)
        )
        with patch.object(scanner, "_get", return_value=_fake_response(403, "")):
            result = ScanResult("http://example.com")
            scanner._scan_url("http://example.com/admin/", result, depth=0)

        self.assertIn("forbidden", events)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. DirectoryScanner — URL normalization
# ═══════════════════════════════════════════════════════════════════════════════

class TestURLNormalization(unittest.TestCase):

    def test_scan_adds_http_scheme(self):
        """scan() should add http:// if missing."""
        scanner = DirectoryScanner(results_dir="results", max_depth=0)
        scanner.wordlist = []  # skip wordlist probing

        with patch.object(scanner, "_scan_url") as mock_scan, \
             patch.object(scanner, "_save_result"):
            scanner.scan("example.com")
            call_args = mock_scan.call_args[0][0]
            self.assertTrue(call_args.startswith("http://"),
                            f"Expected http://, got: {call_args}")

    def test_scan_keeps_https(self):
        scanner = DirectoryScanner(results_dir="results", max_depth=0)
        scanner.wordlist = []

        with patch.object(scanner, "_scan_url") as mock_scan, \
             patch.object(scanner, "_save_result"):
            scanner.scan("https://example.com")
            call_args = mock_scan.call_args[0][0]
            self.assertTrue(call_args.startswith("https://"))


# ═══════════════════════════════════════════════════════════════════════════════
# 10. DirectoryScanner — stop mechanism
# ═══════════════════════════════════════════════════════════════════════════════

class TestStopMechanism(unittest.TestCase):

    def test_stop_sets_event(self):
        scanner = DirectoryScanner(results_dir="results")
        self.assertFalse(scanner._stop_event.is_set())
        scanner.stop()
        self.assertTrue(scanner._stop_event.is_set())

    def test_stop_emits_stopped_event(self):
        events = []
        scanner = DirectoryScanner(
            results_dir="results",
            callback=lambda e, d: events.append(e)
        )
        scanner.stop()
        self.assertIn("stopped", events)

    def test_scan_clears_stop_event_at_start(self):
        """A new scan() call should clear the stop event."""
        scanner = DirectoryScanner(results_dir="results", max_depth=0)
        scanner.wordlist = []
        scanner._stop_event.set()  # pre-stopped

        with patch.object(scanner, "_scan_url"), \
             patch.object(scanner, "_save_result"):
            scanner.scan("http://example.com")

        self.assertFalse(scanner._stop_event.is_set())


# ═══════════════════════════════════════════════════════════════════════════════
# 11. DirectoryScanner — result saving
# ═══════════════════════════════════════════════════════════════════════════════

class TestResultSaving(unittest.TestCase):

    def test_save_result_creates_json_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = DirectoryScanner(results_dir=tmpdir)
            result = ScanResult("http://testsite.com")
            result.add_open_dir("http://testsite.com/files/", [], False, "")
            result.finalize()

            scanner._save_result(result)

            files = os.listdir(tmpdir)
            json_files = [f for f in files if f.endswith(".json")]
            self.assertEqual(len(json_files), 1)

            with open(os.path.join(tmpdir, json_files[0])) as f:
                data = json.load(f)

            self.assertEqual(data["domain"], "testsite.com")
            self.assertEqual(len(data["open_dirs"]), 1)

    def test_save_result_filename_format(self):
        """Filename should follow <domain>_<timestamp>.json pattern."""
        import re
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = DirectoryScanner(results_dir=tmpdir)
            result = ScanResult("http://example.co.in")
            result.finalize()
            scanner._save_result(result)

            files = os.listdir(tmpdir)
            self.assertEqual(len(files), 1)
            # Allow both . and _ as separators from domain
            self.assertRegex(files[0], r".*example.*\.json")


# ═══════════════════════════════════════════════════════════════════════════════
# 12. Folder / project structure integrity checks
# ═══════════════════════════════════════════════════════════════════════════════

class TestProjectStructure(unittest.TestCase):
    """Sanity checks that the DirHawk project layout is intact."""

    BASE = os.path.dirname(__file__)

    def _path(self, *parts):
        return os.path.join(self.BASE, *parts)

    def test_main_py_exists(self):
        self.assertTrue(os.path.isfile(self._path("main.py")))

    def test_server_py_exists(self):
        self.assertTrue(os.path.isfile(self._path("server.py")))

    def test_scanner_package_exists(self):
        self.assertTrue(os.path.isdir(self._path("scanner")))

    def test_scanner_init_exists(self):
        self.assertTrue(os.path.isfile(self._path("scanner", "__init__.py")))

    def test_scanner_core_exists(self):
        self.assertTrue(os.path.isfile(self._path("scanner", "core.py")))

    def test_scanner_proxy_exists(self):
        self.assertTrue(os.path.isfile(self._path("scanner", "proxy.py")))

    def test_scanner_ai_analyzer_exists(self):
        self.assertTrue(os.path.isfile(self._path("scanner", "ai_analyzer.py")))

    def test_wordlists_dir_exists(self):
        self.assertTrue(os.path.isdir(self._path("wordlists")))

    def test_default_wordlist_exists(self):
        self.assertTrue(os.path.isfile(self._path("wordlists", "common_dirs.txt")))

    def test_default_wordlist_not_empty(self):
        path = self._path("wordlists", "common_dirs.txt")
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        self.assertGreater(len(lines), 0, "common_dirs.txt has no entries")

    def test_results_dir_exists(self):
        self.assertTrue(os.path.isdir(self._path("results")))

    def test_ui_dir_exists(self):
        self.assertTrue(os.path.isdir(self._path("ui")))

    def test_requirements_txt_exists(self):
        self.assertTrue(os.path.isfile(self._path("requirements.txt")))

    def test_scanner_importable(self):
        """The scanner package should import cleanly."""
        try:
            from scanner import DirectoryScanner, ProxyConfig
        except ImportError as e:
            self.fail(f"scanner package failed to import: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print(" DirHawk Test Suite")
    print("=" * 60)
    unittest.main(verbosity=2)
