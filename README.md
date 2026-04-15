# CyberHunter

AI-powered autonomous bug bounty hunting platform. A single AI agent (via OpenRouter) thinks, adapts, and hunts vulnerabilities like a human pro — streamed live to a web dashboard.

## Architecture

- **Frontend**: Next.js 16 + shadcn/ui + Tailwind (dark cybersecurity theme)
- **Backend**: Python FastAPI + WebSocket + SQLite
- **AI Brain**: OpenRouter API (Claude, GPT-4, Gemini, Llama — user picks)
- **Go Scanners**: High-perf HTTP fuzzer, crawler, DNS resolver
- **Knowledge Base**: 19 vuln types, 12 tech profiles, 5 bypass playbooks from AllAboutBugBounty

## Quick Start

### 1. Backend

```bash
cd backend
cp .env.example .env  # Add your OPENROUTER_API_KEY
cd ..
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

### 3. Go Scanners (optional)

```bash
cd goscanners
go build -o ../goscanners-bin ./cmd/
```

Open [http://localhost:3000](http://localhost:3000), enter a target, click **Start Hunt**.

## Testing

```bash
source .venv/bin/activate
python -m pytest tests/ -v
```

## Project Structure

```
bestCybertool/
├── frontend/          Next.js 16 web dashboard
├── backend/           Python FastAPI backend
│   ├── agent/         AI agent engine + OpenRouter client
│   ├── knowledge/     YAML vulnerability playbooks
│   ├── tools/         Recon + scanner + validator implementations
│   ├── reporting/     Report generator (MD/HTML/JSON)
│   └── db/            SQLite models
├── goscanners/        Go high-performance scanners
└── tests/             Unit + integration tests
```

## Vulnerability Coverage

XSS, SQLi, SSRF, NoSQLi, LFI/RFI, IDOR, SSTI, CRLF, CSRF, Host Header Injection, File Upload, OAuth, JWT, Cache Poisoning, Race Conditions, 403/2FA/429/Captcha Bypass, Technology-specific CVEs (Laravel, WordPress, Jenkins, Jira, Nginx, Grafana, Confluence, Apache, HAProxy).

## License

For authorized security testing only.