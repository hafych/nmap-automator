# Nmap Automator

An async, security-focused Nmap service for authorized network assessments. It combines a
Quart API, scheduled scans, encrypted result storage, a browser dashboard, Kali tool
inventory, and AI-readable reporting and recon plans.

> Use this project only on systems you own or are explicitly authorized to assess.
> Unauthorized scanning may be illegal and disruptive.

## What it provides

- Immediate and recurring Nmap scans: TCP, SYN, UDP, OS, aggressive, and ping discovery.
- API-key authentication, per-client rate limiting, request-size limits, scan concurrency
  limits, target-range limits, and total scan timeouts.
- Fernet-encrypted results written atomically with owner-only file permissions.
- A built-in operator dashboard at `/` with tasks, results, JSON/JSONL views, tool inventory,
  and recon planning.
- Telegram notifications when configured.
- A standalone `kali_ai_scan.py` CLI that creates raw XML plus JSON, JSONL, Markdown, and a
  manifest suitable for GPT, Claude, or another analysis workflow.
- XXE-safe XML parsing and shell-safe generation of follow-up recon commands.

## Requirements

- Python 3.10 or newer.
- Nmap available on `PATH`.
- A Fernet key and a strong API token.

Install Nmap first:

```bash
# Debian, Ubuntu, Kali
sudo apt-get update
sudo apt-get install -y nmap

# macOS
brew install nmap
```

Some profiles (`SYN`, `UDP`, `OS`, and parts of `Aggressive`) need elevated network
privileges. The default profile is unprivileged `TCP`.

## Quick start

```bash
git clone https://github.com/hafych/nmap-automator.git
cd nmap-automator

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

cp .env.example .env
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
openssl rand -hex 32
```

Put the generated values into `.env` as `FERNET_KEY` and `API_AUTH_TOKEN`, then start the
service:

```bash
python autonmap.py
```

The service binds to `127.0.0.1:5000` by default. Open
[http://127.0.0.1:5000](http://127.0.0.1:5000), enter the API token in the dashboard, and
run a TCP scan against an authorized target.

## Configuration

All options are environment variables and may be placed in `.env`.

| Variable | Default | Purpose |
| --- | ---: | --- |
| `FERNET_KEY` | required | Key used to encrypt stored results. |
| `API_AUTH_TOKEN` | required | Token expected in the API authentication header. |
| `API_AUTH_REQUIRED` | `true` | Disabling authentication is intended only for isolated local development. |
| `API_AUTH_HEADER` | `X-API-KEY` | Header carrying the API token. |
| `APP_HOST` | `127.0.0.1` | Bind address. Use `0.0.0.0` only behind appropriate network controls. |
| `APP_PORT` | `5000` | Listen port. |
| `MAX_CONCURRENT_SCANS` | `2` | Maximum scans running concurrently. |
| `MAX_SCHEDULED_TASKS` | `100` | Maximum recurring scans retained at once. |
| `SCAN_TIMEOUT_SECONDS` | `1800` | Total Nmap process timeout. |
| `NMAP_HOST_TIMEOUT_SEC` | `300` | Nmap per-host timeout. |
| `NMAP_MAX_RETRIES` | `2` | Nmap probe retries. |
| `MAX_TARGET_ADDRESSES` | `4096` | Largest accepted CIDR range. |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Maximum JSON request body size. |
| `MAX_REQUESTS_PER_WINDOW` | `10` | Per-client request limit for costly endpoints. |
| `MAX_RATE_LIMIT_CLIENTS` | `10000` | Maximum number of client buckets kept in memory. |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window. |
| `MIN_SCHEDULE_INTERVAL_MINUTES` | `1` | Smallest allowed recurring-scan interval. |
| `MAX_SCHEDULE_INTERVAL_MINUTES` | `10080` | Largest allowed recurring-scan interval (one week). |
| `RESULTS_DIR` | `encrypted_results` | Encrypted result directory. |
| `SCAN_LOG_PATH` | `logs/scan_log.txt` | Rotating application log. |
| `TOOL_INVENTORY_CACHE_SECONDS` | `300` | Kali inventory cache lifetime. |
| `INITIAL_TASKS` | `[]` | JSON array of recurring scans loaded at startup. |
| `TELEGRAM_BOT_TOKEN` | empty | Optional Telegram bot token. |
| `TELEGRAM_CHAT_ID` | empty | Optional Telegram destination. |

Example recurring task:

```dotenv
INITIAL_TASKS=[{"target":"192.168.1.0/24","scan_type":"TCP","interval":30}]
```

## API

Health and dashboard routes are public. Operational routes require the configured API token
unless authentication was explicitly disabled.

```bash
export API_TOKEN='replace-with-your-token'

# Health and API description
curl http://127.0.0.1:5000/health
curl http://127.0.0.1:5000/api/docs

# Immediate scan
curl -X POST http://127.0.0.1:5000/scan \
  -H "X-API-KEY: $API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","scan_type":"TCP"}'

# Recurring scan, every 30 minutes
curl -X POST http://127.0.0.1:5000/schedule \
  -H "X-API-KEY: $API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target":"192.168.1.0/24","scan_type":"TCP","interval":30}'

# List and cancel scheduled scans
curl -H "X-API-KEY: $API_TOKEN" http://127.0.0.1:5000/tasks
curl -X DELETE -H "X-API-KEY: $API_TOKEN" \
  http://127.0.0.1:5000/tasks/192.168.1.0%2F24-TCP
```

Supported `scan_type` values are `TCP`, `SYN`, `UDP`, `OS`, `Aggressive`, and `Ping`.
Targets may be an IP, a bounded CIDR network, `localhost`, or a syntactically valid DNS name.

## Kali inventory and recon planning

The inventory endpoint checks official Kali metapackages, locally installed packages, and
commands. `expand=1` follows metapackage dependencies and is therefore slower.

```bash
curl -H "X-API-KEY: $API_TOKEN" \
  'http://127.0.0.1:5000/tools?expand=0'

curl -H "X-API-KEY: $API_TOKEN" \
  'http://127.0.0.1:5000/tools/ai-context?format=jsonl&expand=0'
```

A parsed scan response can be turned into non-exploitative, service-specific next steps:

```bash
curl -X POST \
  -H "X-API-KEY: $API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @scan-result.json \
  'http://127.0.0.1:5000/recon/plan?format=markdown'
```

The planner does not execute recommendations. It validates and shell-quotes scan fields,
labels each command as `ready`, `missing`, or `unknown`, and leaves execution to the operator.

## AI-readable CLI

Run Nmap and create an artifact bundle:

```bash
python kali_ai_scan.py deps
python kali_ai_scan.py run 127.0.0.1 \
  --profile tcp \
  --scan-timeout 1800 \
  --out ai_reports
```

Or safely import existing Nmap XML:

```bash
python kali_ai_scan.py parse nmap.xml --out ai_reports/imported-scan
```

Each bundle contains:

- `nmap.xml` — canonical raw Nmap output.
- `hosts.json` — structured hosts, ports, and services.
- `observations.jsonl` — one compact host or service observation per line.
- `summary.md` — human-readable summary.
- `manifest.json` — provenance, toolchain state, paths, and statistics.

Imported XML is parsed with `defusedxml` and capped at 64 MiB.

## Encrypted results

API scan results are stored only in encrypted form. Files are atomically replaced and created
with mode `0600` on POSIX systems.

```bash
# Print plaintext
python decrypt.py encrypted_results/<result>.json

# Write plaintext to a file
python decrypt.py encrypted_results/<result>.json -o result.json
```

Back up `FERNET_KEY` securely. Existing result files cannot be recovered if the key is lost.

## Docker

Create `.env` with `FERNET_KEY` and `API_AUTH_TOKEN`, then run:

```bash
docker compose up --build -d
docker compose ps
docker compose logs -f
```

The Compose configuration binds the service to host loopback, runs as a non-root user, uses a
read-only root filesystem, enables `no-new-privileges`, and persists only logs and encrypted
results. Privileged scan types are intentionally not enabled by the default container profile.

To build directly:

```bash
docker build -f dockerfile -t nmap-automator .
docker run --rm \
  -p 127.0.0.1:5000:5000 \
  -e API_AUTH_TOKEN \
  -e FERNET_KEY \
  nmap-automator
```

## Development

```bash
python -m pip install -r requirements-dev.txt

ruff format --check .
ruff check .
python -m coverage run -m unittest discover -v
python -m coverage report
bandit -q -ll -r . -x ./.venv,./test_autonmap.py,./test_decrypt.py,./test_kali_ai_scan.py,./test_recon_planner.py,./test_tool_inventory.py
pip-audit -r requirements.txt
```

CI runs the test suite on Python 3.10, 3.12, and 3.14, enforces coverage, checks formatting and
linting, scans dependencies for known vulnerabilities, and runs Bandit. Dependabot tracks pip,
GitHub Actions, and Docker updates.

## Project layout

| Path | Responsibility |
| --- | --- |
| `autonmap.py` | Quart API, validation, scheduling, scanning, encryption, and shutdown. |
| `ui.py` | Self-contained operator dashboard. |
| `kali_ai_scan.py` | Safe Nmap runner, XML parser, and artifact generator. |
| `tool_inventory.py` | Kali package and command inventory. |
| `recon_planner.py` | Service-aware, AI-readable follow-up plans. |
| `decrypt.py` | Fernet result decryption utility. |

| `test_*.py` | Unit and async API regression tests. |

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).
