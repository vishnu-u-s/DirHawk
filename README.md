# 🦅 DirHawk — Open Directory Scanner

> AI-powered open directory scanner for authorized VAPT engagements and bug bounty recon.
> It doesn't just find exposed directories — it tells you **which ones actually matter**.

**198-entry wordlist • AI sensitivity analysis • Real-time Web UI • Zero false positives**

---

## 🎯 What It Does

```bash
python main.py -t http://target.com
```

DirHawk probes for publicly exposed directory listings and flags sensitive ones using keyword matching and optional LLM-based analysis.

---

## ⚡ Key Features

| Feature | Details |
|---------|---------|
| **Concurrent probing** | Threaded workers scan a 198-entry wordlist fast |
| **Zero false positives** | Confirms open directories via 8 server signatures ("Index of /", Apache, Nginx, ParentDir) |
| **Recursive enumeration** | Crawls subdirectories automatically (configurable depth, default: 3) |
| **37 sensitivity patterns** | Aadhaar, PAN, passport, bank/IFSC, GST, payroll, audit logs, KYC, CCTV, medical records, credentials |
| **AI sensitivity analysis** | LLM reviews each directory and returns: `SENSITIVE: reason` or `NOT_SENSITIVE: reason` |
| **Bring your own model** | Claude, any OpenAI-compatible API, or fully local models via LiteLLM/Ollama |
| **Bulk target scanning** | Scan entire authorized scope lists in one run |
| **Proxy support** | SOCKS5 / HTTP proxy routing (Tor, Burp compatible) |
| **Real-time Web UI** | SocketIO streams every discovery live with stat cards and scan history |
| **Auto-saved reports** | JSON results per domain with full file listings and sensitivity verdicts |

---

## 🖥️ Demo

<!-- Add demo GIF or video here -->
> 📹 *Demo video/GIF coming soon — shows a full scan with AI sensitivity analysis*

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. CLI mode
```bash
# Single target
python main.py -t http://target.com

# Bulk targets from file
python main.py -T domains.txt

# With SOCKS5 proxy
python main.py -t http://target.com --proxy socks5://127.0.0.1:9050

# AI sensitivity analysis mode (bring your own API key)
python main.py -t http://target.com --mode ai \
  --ai-url https://api.openai.com/v1 \
  --ai-key YOUR_API_KEY \
  --ai-model gpt-4o

# Or use a local model via LiteLLM/Ollama
python main.py -t http://target.com --mode ai \
  --ai-url http://localhost:11434/v1 \
  --ai-key ollama \
  --ai-model llama3

# List available AI models
python main.py --list-models --ai-url https://api.openai.com/v1 --ai-key YOUR_API_KEY
```

### 3. Web UI mode
```bash
python main.py --ui
# Opens http://localhost:5000 in your browser
```

---

## 🔧 CLI Options

```
-t, --target URL        Single target URL
-T, --targets FILE      Bulk targets file (one URL per line)
--proxy PROXY           socks5://host:port or http://host:port
--timeout N             Request timeout in seconds (default: 10)
--workers N             Concurrent threads (default: 10)
--depth N               Max recursive enumeration depth (default: 3)
--wordlist FILE         Custom wordlist path
--mode normal|ai        Scan mode (default: normal)
--ai-url URL            AI API base URL (OpenAI-compatible)
--ai-key KEY            AI API key
--ai-model MODEL        Model name to use
--ai-scope all|flagged  Run AI on all dirs or keyword-flagged only (default: flagged)
--list-models           List available models and exit
--ui                    Launch web UI instead of CLI
--output DIR            Results directory (default: results/)
```

---

## 📁 Output Format

Results are saved as JSON in `results/<domain>_<timestamp>.json`:

```json
{
  "target": "http://target.com",
  "open_directories": [...],
  "sensitive_directories": [...],
  "ai_analysis": {...}
}
```

---

## 🗂️ Codebase

```
DirHawk/
├── main.py              # CLI entry point
├── server.py            # Flask + SocketIO Web UI server
├── requirements.txt
├── scanner/
│   ├── core.py          # Scanner engine (wordlist, recursive, detection)
│   ├── ai_analyzer.py   # LLM API integration (OpenAI-compatible)
│   ├── proxy.py         # SOCKS5/HTTP proxy config
│   └── __init__.py
├── wordlists/
│   └── common_dirs.txt  # 198 common directory names
├── results/             # Auto-created, stores scan JSON files
└── ui/
    ├── index.html
    ├── css/style.css
    └── js/app.js
```

---

## 🔁 Part of Probr

DirHawk started as a standalone tool — then was integrated into [Probr](https://github.com/VishnuUS/probr) as **Layer 10** of the full recon pipeline. Build once, integrate everywhere.

---

## 🛡️ Responsible Use

This tool is designed for **authorized** VAPT engagements and bug bounty programs only.
- Always obtain written permission before scanning any target
- Never scan systems you do not own or have explicit authorization for
- All sensitive exposures should be responsibly disclosed to the target organization

---

## 👤 Author

**Vishnu US** — VAPT Engineer

- 🔗 LinkedIn: [linkedin.com/in/vishnu-us-5314b6205](https://linkedin.com/in/vishnu-us-5314b6205)
- 🐙 GitHub: [github.com/VishnuUS](https://github.com/VishnuUS)
- 📧 Email: vishnuusbug@gmail.com

---

## 🔗 Related Projects

- [Probr](https://github.com/VishnuUS/probr) — Vulnerability Recon & Finder Engine (DirHawk is integrated as Layer 10)
- [AI Bug Bounty Tool](https://github.com/VishnuUS/ai-bug-bounty-tool) — MCP server with 104 security testing tools
