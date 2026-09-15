"""
main.py — DirHawk CLI entry point
"""

import os
import sys
import json
import argparse
import webbrowser
import threading

import urllib3
urllib3.disable_warnings()

from scanner.core import DirectoryScanner
from scanner.ai_analyzer import AIAnalyzer
from scanner.proxy import ProxyConfig

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C_RED    = Fore.RED
    C_GREEN  = Fore.GREEN
    C_YELLOW = Fore.YELLOW
    C_CYAN   = Fore.CYAN
    C_MAGENTA= Fore.MAGENTA
    C_RESET  = Style.RESET_ALL
    C_BOLD   = Style.BRIGHT
except ImportError:
    C_RED = C_GREEN = C_YELLOW = C_CYAN = C_MAGENTA = C_RESET = C_BOLD = ""


BANNER = f"""
{C_CYAN}{C_BOLD}
  ██████╗ ██╗██████╗ ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
  ██╔══██╗██║██╔══██╗██║  ██║██╔══██╗██║    ██║██║ ██╔╝
  ██║  ██║██║██████╔╝███████║███████║██║ █╗ ██║█████╔╝ 
  ██║  ██║██║██╔══██╗██╔══██║██╔══██║██║███╗██║██╔═██╗ 
  ██████╔╝██║██║  ██║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
  ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
{C_RESET}  {C_YELLOW}Open Directory Scanner{C_RESET}  |  {C_MAGENTA}v1.0.0{C_RESET}
  {C_CYAN}VAPT Toolset — Use responsibly on authorized targets only{C_RESET}
"""


# ─── CLI callback ─────────────────────────────────────────────────────────────
def cli_callback(event: str, data: dict):
    if event == "start":
        print(f"\n{C_CYAN}[>] Target: {data['target']}{C_RESET}")
        if data.get("proxy") and "direct" not in data.get("proxy", ""):
            print(f"{C_YELLOW}[~] Proxy: {data['proxy']}{C_RESET}")

    elif event == "found":
        flag = f"{C_RED}[SENSITIVE]{C_RESET}" if data["is_sensitive"] else f"{C_GREEN}[OPEN]{C_RESET}"
        print(f"  {flag} {data['url']}  ({data['file_count']} items)")
        if data.get("reason"):
            print(f"        {C_YELLOW}↳ {data['reason']}{C_RESET}")

    elif event == "progress":
        print(f"  {C_CYAN}...{C_RESET} {data.get('msg', '')}", end="\r")

    elif event == "saved":
        print(f"\n{C_GREEN}[✓] Saved: {data['path']}{C_RESET}")

    elif event == "done":
        d = data
        print(f"\n{C_BOLD}{'─'*55}{C_RESET}")
        print(f"  Scan complete for {C_CYAN}{d['domain']}{C_RESET}")
        print(f"  Checked : {d['summary']['total_checked']}")
        print(f"  Open    : {C_GREEN}{d['summary']['open_dirs_found']}{C_RESET}")
        print(f"  Sensitive: {C_RED}{d['summary']['sensitive_dirs_found']}{C_RESET}")
        print(f"{C_BOLD}{'─'*55}{C_RESET}")

    elif event == "stopped":
        print(f"\n{C_YELLOW}[!] {data['msg']}{C_RESET}")

    elif event == "ai_start":
        print(f"\n{C_MAGENTA}[AI] {data['msg']}{C_RESET}")

    elif event == "ai_progress":
        print(f"{C_MAGENTA}[AI] {data['msg']}{C_RESET}")

    elif event == "ai_done":
        print(f"\n{C_MAGENTA}{'═'*55}{C_RESET}")
        print(f"{C_BOLD}AI Analysis Result:{C_RESET}")
        print(data.get("response", ""))
        print(f"{C_MAGENTA}{'═'*55}{C_RESET}")

    elif event == "bulk_progress":
        print(f"\n{C_CYAN}[{data['current']}/{data['total']}] Scanning: {data['target']}{C_RESET}")

    elif event == "error":
        print(f"{C_RED}[ERR] {data.get('msg', data)}{C_RESET}")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="dirhawk",
        description="DirHawk — Open Directory Scanner with AI Analysis",
    )

    # Target options
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-t", "--target", metavar="URL",
                       help="Single target URL (e.g. http://example.com)")
    group.add_argument("-T", "--targets", metavar="FILE",
                       help="File with list of targets (one per line)")

    # Network
    parser.add_argument("--proxy", metavar="PROXY",
                        help="SOCKS5/HTTP proxy (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--workers", type=int, default=10,
                        help="Concurrent threads for wordlist probing (default: 10)")
    parser.add_argument("--depth", type=int, default=3,
                        help="Max recursive depth (default: 3)")
    parser.add_argument("--wordlist", metavar="FILE",
                        help="Custom wordlist file path")

    # Mode
    parser.add_argument("--mode", choices=["normal", "ai"], default="normal",
                        help="Scan mode: normal or ai (default: normal)")

    # AI options
    parser.add_argument("--ai-url", metavar="URL",
                        help="AI API base URL (e.g. http://10.31.5.112:4000)")
    parser.add_argument("--ai-key", metavar="KEY",
                        help="AI API key")
    parser.add_argument("--ai-model", metavar="MODEL",
                        help="Model to use for AI analysis")
    parser.add_argument("--list-models", action="store_true",
                        help="List available AI models and exit")

    # UI
    parser.add_argument("--ui", action="store_true",
                        help="Launch the web UI instead of CLI mode")

    # Output
    parser.add_argument("--output", metavar="DIR", default="results",
                        help="Results output directory (default: results)")

    args = parser.parse_args()

    # ── UI mode ──────────────────────────────────────────────────────────────
    if args.ui:
        print(f"{C_GREEN}[*] Launching DirHawk UI at http://localhost:5000{C_RESET}")
        from server import app, socketio
        threading.Timer(1.2, lambda: webbrowser.open("http://localhost:5000")).start()
        socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
        return

    # ── List models ───────────────────────────────────────────────────────────
    if args.list_models:
        if not args.ai_url or not args.ai_key:
            print(f"{C_RED}[!] --ai-url and --ai-key required to list models.{C_RESET}")
            sys.exit(1)
        proxy = ProxyConfig(args.proxy)
        analyzer = AIAnalyzer(
            base_url=args.ai_url,
            api_key=args.ai_key,
            proxies=proxy.get_proxies(),
        )
        models = analyzer.list_models()
        print(f"\n{C_GREEN}Available models at {args.ai_url}:{C_RESET}")
        for m in models:
            print(f"  • {m}")
        return

    # ── Parse targets ─────────────────────────────────────────────────────────
    targets = []
    if args.target:
        targets = [args.target]
    elif args.targets:
        if not os.path.exists(args.targets):
            print(f"{C_RED}[!] Targets file not found: {args.targets}{C_RESET}")
            sys.exit(1)
        with open(args.targets) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        parser.print_help()
        sys.exit(0)

    if not targets:
        print(f"{C_RED}[!] No targets to scan.{C_RESET}")
        sys.exit(1)

    # ── AI validation ──────────────────────────────────────────────────────────
    if args.mode == "ai":
        missing = []
        if not args.ai_url:   missing.append("--ai-url")
        if not args.ai_key:   missing.append("--ai-key")
        if not args.ai_model: missing.append("--ai-model")
        if missing:
            print(f"{C_RED}[!] AI mode requires: {', '.join(missing)}{C_RESET}")
            sys.exit(1)

    # ── Run scanner ────────────────────────────────────────────────────────────
    proxy = ProxyConfig(args.proxy)
    if proxy.is_active():
        print(f"{C_YELLOW}[~] Proxy: {args.proxy}{C_RESET}")

    scanner = DirectoryScanner(
        proxy_config=proxy,
        timeout=args.timeout,
        max_workers=args.workers,
        max_depth=args.depth,
        wordlist_path=args.wordlist,
        callback=cli_callback,
        results_dir=args.output,
    )

    try:
        results = scanner.scan_bulk(targets)
    except KeyboardInterrupt:
        scanner.stop()
        print(f"\n{C_YELLOW}[!] Interrupted by user.{C_RESET}")
        sys.exit(0)

    # ── AI analysis ────────────────────────────────────────────────────────────
    if args.mode == "ai":
        all_open = []
        for r in results:
            all_open.extend(r.open_dirs)

        analyzer = AIAnalyzer(
            base_url=args.ai_url,
            api_key=args.ai_key,
            model=args.ai_model,
            proxies=proxy.get_proxies(),
            callback=cli_callback,
        )
        ai_result = analyzer.analyze_directories(all_open)

        # Save AI analysis alongside results
        for r in results:
            ai_path = os.path.join(
                args.output,
                f"{r.domain}_ai_analysis.json".replace(":", "_"),
            )
            with open(ai_path, "w") as f:
                json.dump(ai_result, f, indent=2)
            print(f"{C_GREEN}[✓] AI analysis saved: {ai_path}{C_RESET}")


if __name__ == "__main__":
    main()
