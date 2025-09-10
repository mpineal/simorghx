SimorghX — Scope-Safe, Enterprise-Grade Recon Framework (Async, Pluggable)

Passive/low-impact recon that you can actually ship.
Highlights: async httpx, plugin architecture, scope enforcement, caching, JSON + HTML reports, and a simple -d DOMAIN quick mode.

Table of Contents

What is SimorghX?

Features

Safety & Legal

Install

Quick Start (no YAML)

Config Mode (YAML)

Available Plugins

Outputs

Architecture

Plugin Development Guide

Troubleshooting

Roadmap

Contributing

License

What is SimorghX?

SimorghX is a scope-safe recon framework designed for professional red/blue teams and bug bounty workflows. It emphasizes:

Authorization-first: you must explicitly confirm you’re allowed to test.

Scope control: domains/IPs are confined via allowlists.

Low-impact defaults: passive modules by default; “active” modules require an explicit flag.

Pluggability: add your own modules in a few lines.

It’s a clean foundation you can extend to thousands of lines and enterprise workflows.

Features

Two modes of use

Quick CLI: simorghx -d example.com --i-affirm-authorized

Config file: rich YAML configuration and repeatable runs

Async HTTP engine with httpx (HTTP/2, redirects, limits, timeouts)

Plugin architecture (passive by default, opt-in active)

Scope enforcement for domains (and optional IPv4 CIDR)

Caching with SQLite (reduce re-requests)

Reporting

JSON for pipelines/automation

HTML report for stakeholders

Human-friendly TUI with rich

Extendable: add tech fingerprints, screenshots, port scans (active), etc.

Safety & Legal

SimorghX is built around responsible use:

You must pass --i-affirm-authorized (or set it in YAML).

Default plugins are passive/low-impact. Active modules are gated behind --enable-active.

Respect the scope you configure (domains, optional IP CIDRs, blocklists).

Use against assets you own or have written permission to test.

The authors are not responsible for any misuse. You are solely responsible for compliance with laws, contracts, and platform policies.

Install
# 1) Clone this repo
git clone https://github.com/<you>/simorghx.git
cd simorghx

# 2) Create a virtualenv
python3 -m venv venv
source venv/bin/activate         # Windows: venv\Scripts\activate

# 3) Install in editable mode
pip install --upgrade pip
pip install -e .

# (installs) httpx[http2], rich, tldextract, dnspython, pyyaml, pydantic, aiosqlite, jinja2


Requirements

Python 3.10+

Internet access (for CT logs, DNS, etc.)

Quick Start (no YAML)

Run with a domain directly:

simorghx -d example.com --i-affirm-authorized \
  --json report.json --html report.html


Multiple domains:

simorghx -d example.com -d example.org --i-affirm-authorized


Pick plugins explicitly:

simorghx -d example.com --plugins ctlogs,dns_resolve,http_probe,headers_audit \
  --i-affirm-authorized


Control concurrency & timeouts:

simorghx -d example.com --i-affirm-authorized -q 25 -t 12


Enable active modules (if you add any):

simorghx -d example.com --i-affirm-authorized --enable-active --nmap-ports top100


CLI flags overview

-d / --domain            Repeatable root domain(s) in scope
--plugins                Comma-separated plugin list (default sensible set)
--json / --html          Export report to files
-q / --concurrency       Async concurrency (default 15)
-t / --timeout           HTTP timeout per request (default 10s)
-b / --budget            Per-domain “budget” hint plugins may use
--enable-active          Allow active plugins to run
--nmap-ports             Active ports profile (if you add a portscan plugin)
--allow-ip-cidr          Repeatable IPv4 CIDRs allowlist (e.g. 203.0.113.0/24)
--blocklist-host         Repeatable hostnames to skip
--i-affirm-authorized    Required safety confirmation
--signer                 Your name / ticket reference

Config Mode (YAML)

Create simorghx.yaml:

authorization:
  i_affirm_authorized: true
  signer: "Your Name / Ticket-123"

scope:
  allow_domains:
    - example.com
  allow_ipv4_cidrs: []      # e.g. ["203.0.113.0/24"]
  blocklist_hosts: []

limits:
  concurrency: 15
  per_domain_budget: 6
  request_timeout: 10

active:
  enable_active: false
  nmap_ports: "top1000"     # used only if enable_active=true

report:
  out_json: "report.json"
  out_html: "report.html"

plugins:
  - ctlogs
  - dns_resolve
  - http_probe
  - robots_sitemap
  - headers_audit
  - cors_audit
  - secrets_grep
  # - buckets_guess          # optional example

targets:
  roots:
    - example.com
  # seeds_subdomains: ["dev.example.com", "api.example.com"]


Run:

simorghx -c simorghx.yaml
# or:
python -m simorghx.cli -c simorghx.yaml

Available Plugins
Plugin	Type	What it does
ctlogs	Passive	Enumerate subdomains via Certificate Transparency (crt.sh)
dns_resolve	Passive	Resolve A/AAAA/CNAME/MX/NS/TXT
http_probe	Passive	Probe https://host (fallback to http) – status, title, server, headers
robots_sitemap	Passive	Fetch /robots.txt and parse Sitemap: entries
headers_audit	Passive	Simple hygiene checks (HSTS missing, X-Powered-By leaks)
cors_audit	Passive	Safe CORS sniff (checks Access-Control-Allow-Origin)
secrets_grep	Passive	Grep for likely front-end secrets in HTML (lightweight patterns)
buckets_guess	Passive	(Example) Name candidates for buckets based on root domain

All default plugins are passive. You can implement “active” ones and gate them behind --enable-active.

Outputs
JSON

Machine-readable snapshot for pipelines:

{
  "generated_at": 1700000000,
  "subdomains": ["api.example.com", "www.example.com"],
  "dns": { "...": { "A": ["203.0.113.10"], "TXT": [] } },
  "http": {
    "www.example.com": [
      {
        "scheme": "https",
        "status": 200,
        "title": "Example Domain",
        "server": "nginx",
        "x_powered_by": null,
        "hsts": true,
        "redirect_chain": ["https://www.example.com/"]
      }
    ]
  },
  "findings": [
    {
      "kind": "Headers",
      "target": "app.example.com",
      "severity": "Low",
      "description": "Missing Strict-Transport-Security on HTTPS."
    }
  ]
}

HTML

A readable report (report.html) with sections for subdomains, HTTP probe, and findings.

Architecture

Async runtime: asyncio + httpx (HTTP/2, redirects, limits, timeouts)

Plugins: discrete modules returning dictionaries merged into a shared report

Scope enforcement: domain allowlist (and optional IPv4 CIDR)

Caching: SQLite key-value store to reduce repeated lookups

UI: rich for tidy CLI tables and progress indications

Reporting: JSON + HTML (Jinja2 templating)

Project layout

simorghx/
├─ pyproject.toml
├─ simorghx/
│  ├─ cli.py
│  ├─ config.py
│  ├─ scope.py
│  ├─ logger.py
│  ├─ pipeline.py
│  ├─ storage/cache.py
│  ├─ reporting/{json_exporter.py, html_exporter.py}
│  ├─ utils/{http.py, text.py}
│  └─ plugins/
│     ├─ base.py
│     ├─ ctlogs.py
│     ├─ dns_resolve.py
│     ├─ http_probe.py
│     ├─ robots_sitemap.py
│     ├─ headers_audit.py
│     ├─ cors_audit.py
│     ├─ secrets_grep.py
│     └─ buckets_guess.py (example)
└─ README.md

Plugin Development Guide

Plugin contract

Define name (string) and active (False for passive; set True for active modules).

Implement async def run(self, targets: List[str]) -> Dict[str, Any].

Access context via self.ctx:

self.ctx.cfg — current Config

self.ctx.client — shared httpx.AsyncClient

self.ctx.cache — SQLite cache helper

self.ctx.shared — accumulated report data (e.g., subdomains, http, findings)

Minimal plugin template

# simorghx/plugins/my_plugin.py
from typing import Dict, Any, List
from .base import Plugin, Finding  # optional

class MyPlugin(Plugin):
    name = "my_plugin"
    active = False  # set True if this does active testing

    async def run(self, targets: List[str]) -> Dict[str, Any]:
        # Use self.ctx.client for HTTP requests
        # Read other plugin outputs via self.ctx.shared
        # Return any of: {"subdomains": [...], "dns": {...}, "http": {...}, "findings": [...]}
        return {"findings": [{
            "kind": "Example",
            "target": ",".join(targets),
            "severity": "Info",
            "description": "Hello from MyPlugin"
        }]}

def plugin():
    return MyPlugin()


Register plugin

Import factory in simorghx/cli.py (registry dict).

Add to YAML under plugins: or pass via --plugins.

Access previous results

http_map = self.ctx.shared.get("http", {})
subs = self.ctx.shared.get("subdomains", [])


Marking Active

class PortScan(Plugin):
    name = "port_scan"
    active = True  # will only run with --enable-active

Troubleshooting

No module named 'simorghx'

You’re not in the project root or didn’t install the package.

Fix: run from repo root and install:

pip install -e .


Or:

PYTHONPATH=. python -m simorghx.cli -c simorghx.yaml


Authorization error

You must pass --i-affirm-authorized (quick mode) or set authorization.i_affirm_authorized: true in YAML.

HTML/JSON not created

Ensure --json/--html flags (quick mode) or report section in YAML are set and that the process has write permission.

Python version

Ensure Python 3.10+:

python -V


Missing deps

Reinstall:

pip install -e .

Roadmap

Tech fingerprint (Wappalyzer signatures)

Screenshots (Playwright) of key pages (passive fetch + render)

SPF/DMARC mail posture audit

OpenAPI/GraphQL discovery

Optional “active” packs (rate-limited, scope-gated)

More HTML themes and CSV export

Contributing

PRs and issues are welcome!

Keep modules scope-safe by default.

If adding active functionality, guard with active = True and respect --enable-active.

Add documentation and tests where possible.

License

MIT © You. Replace this line with your actual license of choice.

Example Commands Recap
# Quick, no YAML
simorghx -d example.com --i-affirm-authorized --json report.json --html report.html

# Multiple domains
simorghx -d example.com -d example.org --i-affirm-authorized

# With YAML
simorghx -c simorghx.yaml


Enjoy safe, scalable recon ✨
