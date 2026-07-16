# Recon Operator — полный аудит, исправления и backlog

Обновлено: 2026-07-16. Этот файл — живой список: выполненные пункты отмечены `[x]` и зачёркнуты; незачёркнутые пункты остаются рекомендациями и могут быть возвращены в работу после повторной проверки.

> **Полный roadmap улучшений:** см. [IMPROVEMENT_PLAN.md](IMPROVEMENT_PLAN.md) (приоритеты P0–P3, релизы D–G, DoD, риски).

## Итог

- **Release C partial (2026-07-15):** hybrid discovery (Naabu/RustScan), SQLite state (`STATE_DB_PATH`), v1.4.0.
- **Release B + rebrand (2026-07-15):** product **Recon Operator** (не Nmap-only). Профили Version/Safe/Vuln/Full, optional ports/scripts, XML import, scan diff, UI multi-tool controls.
- **Release A (2026-07-15):** единый `scan_engine` (subprocess + defused XML, без `python-nmap`), async jobs (`POST /scan` → 202 + `/jobs`), history API (`/results`), EN error model, retention, UI history + job polling.
- Ранее: UI a11y, atomic encrypted writes, decrypt UX, CI matrix, Docker hardening, recon planner, Kali inventory.
- Quality gate после Release A: 55 tests pass; coverage gate raised to 58%; Ruff/Bandit — pass.
- Dockerfile и Compose: static audit pass. Runtime Docker build may still need owner Docker Desktop setup.

## Критерии готовности

- [x] ~~Все локально доступные команды и функции продукта проверены безопасно, без внешних целей.~~ Nmap запускался только против `127.0.0.1`.
- [x] ~~UI проверен реальным браузером на desktop, 390 px и 320 px.~~ Горизонтального overflow нет; minimum interactive target — 44 px.
- [x] ~~API, задачи, шифрование, planner, inventory и artifacts проверены тестами и smoke-сценариями.~~
- [x] ~~Форматирование, линтер, coverage, Bandit и dependency audit пройдены.~~
- [x] ~~Перед изменениями выполнен GitNexus impact-анализ.~~ Все изменённые индексированные символы получили риск `LOW`; HIGH/CRITICAL не было.
- [ ] Runtime Docker build/healthcheck на машине с уже настроенным Docker daemon без privilege prompt.

## 0. Исходное состояние и воспроизводимость

- [x] ~~Сохранить существующие пользовательские изменения.~~ Не затронуты pre-existing изменения в `.claude/skills/gitnexus/*`, `AGENTS.md`, `CLAUDE.md`.
- [x] ~~Проверить system Python.~~ Python 3.14.4; без dev dependencies discovery ожидаемо дал 5 ImportError.
- [x] ~~Создать изолированное окружение и установить pins.~~ `.venv`, `pip check` — no broken requirements.
- [x] ~~Обновить GitNexus index.~~ Локальный `analyze --pdg`: 1,471 nodes, 4,248 edges, 17 clusters, 85 flows; import cycles — 0.
- [x] ~~Проверить production dependencies.~~ Все pins актуальны на 2026-07-10; `pip-audit` не нашёл CVE.
- [x] ~~Проверить dev dependencies.~~ Bandit 1.9.4, pip-audit 2.10.1 и Ruff 0.15.21 актуальны; coverage обновлён `7.13.5 → 7.15.0`.
- [x] ~~Проверить README quick start.~~ Установка, `kali_ai_scan.py deps/run/parse`, API curl-сценарии и decrypt соответствуют реализации; документация дополнена правами CLI artifacts.

Источники актуальности: [python-telegram-bot](https://pypi.org/project/python-telegram-bot/), [cryptography](https://pypi.org/project/cryptography/), [python-nmap](https://pypi.org/project/python-nmap/), [Quart](https://pypi.org/project/Quart/), [Flask](https://pypi.org/project/Flask/), [python-dotenv](https://pypi.org/project/python-dotenv/), [defusedxml](https://pypi.org/project/defusedxml/), [Ruff](https://pypi.org/project/ruff/), [Bandit](https://pypi.org/project/bandit/), [coverage](https://pypi.org/project/coverage/), [pip-audit](https://pypi.org/project/pip-audit/).

## 1. UI/UX и доступность

- [x] ~~Проверить первый экран без токена.~~ UI загружается, API показывает `auth needed`, toast — `401` с названием header.
- [x] ~~Проверить API token.~~ Хранится только в `sessionStorage`, не попадает в URL или server log; password input маскирует значение.
- [x] ~~Проверить Run Scan.~~ Ping scan возвращает 1 host/up; busy-state блокирует повторную отправку; success-toast сохраняется после refresh.
- [x] ~~Проверить Schedule и Cancel.~~ Task появляется с running-state; Cancel имеет имя с task id и browser confirmation; API delete удаляет test task.
- [x] ~~Проверить Tools, Recon plan и copy.~~ Inventory: 15 ready/51 checked/36 missing/13 profiles; JSONL context и current view копируются.
- [x] ~~Проверить adaptive layout.~~ 736/390/320 px без обрезки и horizontal scroll; на 320 px `scrollWidth == clientWidth == 320`.
- [x] ~~Проверить keyboard focus и touch targets.~~ `:focus-visible` — solid 3 px; buttons/input/select/tabs — минимум 44 px.
- [x] ~~Проверить semantics.~~ Status uses live region; outputs имеют labels; tabs — tablist/tab/tabpanel и корректный `aria-selected`.
- [x] ~~Проверить error UX.~~ HTTP status добавляется к server detail; clipboard failure имеет понятный fallback; 401/429/504 покрыты.
- [x] ~~Проверить XSS-sensitive rendering.~~ Task id вставляется через `textContent`; targets/plan fields валидируются; command-injection test проходит.
- [x] ~~Проверить browser console.~~ После полного smoke-test warning/error — 0.

Реализованные UI fixes:

| ID | Приоритет | Исправление | Проверка |
| --- | --- | --- | --- |
| UI-001 | P1 | Видимый keyboard focus, ARIA, labels и 44 px targets | Browser AX tree, computed style и viewport metrics |
| UI-002 | P2 | Scan/schedule/cancel toast больше не перезаписывается generic refresh | Реальный browser workflow |
| UI-003 | P2 | Confirm перед удалением scheduled task и task-specific accessible name | Native confirm обнаружен, API deletion проверен |
| UI-004 | P2 | HTTP status в ошибках и fallback при clipboard failure | 401 browser smoke + regression assertion |

## 2. API и пользовательские сценарии

- [x] ~~`GET /` и `GET /ui`.~~ 200, HTML dashboard, `Cache-Control: no-store`, `X-Frame-Options: DENY`, CSP.
- [x] ~~`GET /health`.~~ 200 healthy, Nmap availability, Fernet state и limits без раскрытия secrets.
- [x] ~~`GET /api/docs`.~~ Все 8 routes и auth-header соответствуют реализации.
- [x] ~~`GET /tasks`.~~ Без token — 401; с token — список; завершённые tasks очищаются.
- [x] ~~`POST /scan`.~~ Target/type validation, bounded CIDR, timeout, concurrency guard и rate limit проверены unit/smoke tests.
- [x] ~~Scan result persistence.~~ Результат на диске зашифрован Fernet, mode `0600`, plaintext JSON отсутствует.
- [x] ~~`POST /schedule` + `DELETE /tasks/<id>`.~~ Создание, немедленный первый run, list, cancellation и graceful cleanup — pass.
- [x] ~~`GET /tools`.~~ Compact inventory, platform fallback, cache и expanded profile path — pass.
- [x] ~~`GET /tools/ai-context`.~~ Valid JSONL: summary + tool records.
- [x] ~~`POST /recon/plan`.~~ JSON и Markdown, empty/non-empty plan, invalid ports и injection fields — pass.
- [x] ~~Graceful shutdown.~~ SIGINT отменяет фоновые tasks и завершает сервис без повреждения результатов.

Оговорка: сервис intentionally single-operator/single-token; список tasks глобальный. Tenant isolation не заявлен контрактом.

## 3. Инструменты — проверка по очереди

### 3.1 Essential tools (29/29 проверены)

`available` означает, что команда найдена и безопасно ответила на `--version`/`--help` либо показала ожидаемый usage. Для команд, где help возвращает non-zero, наличие подтверждено корректным диагностическим выводом.

| # | Package | Command | Результат локальной проверки |
| ---: | --- | --- | --- |
| 1 | nmap | `nmap` | Готово — 7.99; localhost Ping scan pass |
| 2 | llm-tools-nmap | — | Package/data-only; не установлен на macOS |
| 3 | python3 | `python3` | Готово — 3.14.4 |
| 4 | curl | `curl` | Готово — 8.7.1 |
| 5 | dnsrecon | `dnsrecon` | Missing |
| 6 | dnsutils | `dig` | Готово — usage/version response |
| 7 | enum4linux-ng | `enum4linux-ng` | Missing |
| 8 | jq | `jq` | Готово — 1.7.1 |
| 9 | git | `git` | Готово — 2.50.1 |
| 10 | nikto | `nikto` | Готово — usage response |
| 11 | rpcbind | `rpcinfo` | Готово — usage response |
| 12 | sqlmap | `sqlmap` | Готово — 1.10.5 |
| 13 | smbclient | `smbclient` | Missing |
| 14 | ssh-audit | `ssh-audit` | Missing |
| 15 | sslscan | `sslscan` | Missing |
| 16 | wireshark | `wireshark`, `tshark` | Missing |
| 17 | whatweb | `whatweb` | Готово — 0.6.4 |
| 18 | metasploit-framework | `msfconsole` | Missing |
| 19 | hydra | `hydra` | Готово — 9.6/version response |
| 20 | john | `john` | Missing |
| 21 | hashcat | `hashcat` | Готово — 7.1.2 |
| 22 | aircrack-ng | `aircrack-ng` | Готово — help response |
| 23 | gobuster | `gobuster` | Missing |
| 24 | ffuf | `ffuf` | Готово — 2.1.0-dev/usage response |
| 25 | feroxbuster | `feroxbuster` | Missing |
| 26 | seclists | — | Package/data-only; не установлен на macOS |
| 27 | exploitdb | `searchsploit` | Готово — usage response |
| 28 | dradis | — | Package/data-only; не установлен на macOS |
| 29 | faraday | `faraday` | Missing |

Missing tools не устанавливались автоматически: это security tooling для Kali, а текущая платформа — macOS без `apt/dpkg`; глобальная установка изменила бы систему без пользы для проверки приложения. Inventory корректно сообщает missing и install suggestions.

### 3.2 Profiles и artifacts

- [x] ~~Проверить все 13 Kali profiles.~~ `ai`, `core`, `exploitation`, `forensics`, `passwords`, `radio`, `recon`, `reporting`, `reverse`, `social`, `voip`, `web`, `wireless`; metapackage mappings корректны.
- [x] ~~Проверить non-Debian fallback.~~ `dpkg-query`/`apt-cache` корректно возвращают unavailable/empty dependencies на macOS.
- [x] ~~Проверить inventory JSON/JSONL/Markdown.~~ 32 packages для core+ai; valid JSON; JSONL 33 records; Markdown heading/sections корректны.
- [x] ~~Проверить Nmap XML.~~ Valid parse, invalid root, 64 MiB guard и XXE `EntitiesForbidden`.
- [x] ~~Проверить `kali_ai_scan.py run`.~~ Local Ping: 1 host/up, 0 open ports, 6 output files.
- [x] ~~Проверить `kali_ai_scan.py parse`.~~ Повторный import XML создаёт полный artifact bundle.
- [x] ~~Проверить artifact confidentiality.~~ Directory `0700`; XML/TXT/JSON/JSONL/MD `0600`; derived files пишутся через temporary file + atomic replace.
- [x] ~~Проверить decrypt.~~ Valid key/output mode `0600`; missing/wrong key и damaged token; CLI больше не печатает traceback.

## 4. Backend, надёжность и безопасность

- [x] ~~Concurrency и global-state cleanup.~~ Semaphore, task limit и cleanup finished tasks присутствуют; unit coverage для limit/cleanup.
- [x] ~~Rate limiting.~~ Window/bucket cap и stale eviction протестированы; trusted proxy отключён по умолчанию.
- [x] ~~Injection/path safety.~~ Strict target syntax/CIDR bounds, subprocess without shell, shell-quoted planner, defused XML, sanitized filenames.
- [x] ~~Secrets/logging.~~ API/Fernet tokens не логируются; stored API scan results encrypted; CLI artifacts теперь owner-only.
- [x] ~~Atomic writes и permissions.~~ API encrypted results/decrypt/CLI derived artifacts используют atomic replace и `0600`.
- [x] ~~Timeout/missing subprocess/cancellation.~~ Nmap total timeout, command fallback и cancellation paths проверены.
- [x] ~~HTTP security.~~ no-store, nosniff, DENY, referrer policy, permissions policy и frame-ancestors.
- [x] ~~Production config.~~ Loopback default, auth+Fernet required, debug off, Compose read-only/non-root/no-new-privileges.
- [x] ~~Static security checks.~~ Bandit medium/high — 0; pip-audit production/dev — 0 known vulnerabilities; GitNexus import cycles — 0.
- [ ] GitNexus MCP PDG/taint consumer должен увидеть свежий local `--pdg` index. CLI rebuild успешен, но текущий MCP session продолжил возвращать stale `no PDG layer`; перепроверить после перезапуска MCP.

## 5. Качество, CI и поставка

- [x] ~~`ruff format --check .`.~~ 12 files already formatted.
- [x] ~~`ruff check .`.~~ All checks passed.
- [x] ~~`python -m compileall -q .`.~~ Pass.
- [x] ~~Полный unittest.~~ 41/41 pass на Python 3.14.4.
- [x] ~~Coverage.~~ 62% branch coverage; configured minimum 55%; critical new branches covered.
- [x] ~~Bandit.~~ Medium/high findings — 0.
- [x] ~~pip-audit.~~ Production и dev requirements — no known vulnerabilities.
- [x] ~~Compose config.~~ Required-secret validation работает; с test secrets `docker compose config --quiet` — pass.
- [x] ~~Dockerfile/Compose static audit.~~ `USER app`, read-only root, named writable volumes, loopback port, healthcheck, SIGTERM, 40s grace period.
- [x] ~~CI versions.~~ `actions/checkout@v4 → @v6`, `actions/setup-python@v5 → @v6`; Python matrix 3.10/3.12/3.14 сохранена.
- [x] ~~Dependabot.~~ Weekly pip, GitHub Actions и Docker updates включены.
- [x] ~~GitNexus `detect_changes`.~~ Risk `medium`: результат включает pre-existing пользовательские instruction-файлы и ошибочно относит соседний неизменённый `utc_now` к diff hunk; фактические product changes ограничены UI, CLI artifact/decrypt paths, tests и CI/dependency docs. Три отмеченных inventory/recon flows повторно покрыты unit/API tests.
- [ ] Docker runtime build/up/healthcheck — нужен один раз после разрешения Docker Desktop privileged network setup владельцем машины.

## 6. Приоритизированный backlog улучшений

Эти пункты не являются подтверждёнными поломками текущего single-operator приложения; это следующий уровень hardening/масштабирования.

### Release A — выполнено (2026-07-15)

- [x] ~~Единый scan engine (`scan_engine.py`): subprocess argv + `defusedxml` через `kali_ai_scan.parse_nmap_xml`.~~
- [x] ~~Удалён dependency `python-nmap`.~~
- [x] ~~In-process job queue: `POST /scan` → 202, `GET/DELETE /jobs`, `?wait=1` sync mode.~~
- [x] ~~Results index: `GET /results`, `GET /results/<id>` (decrypt + safe path).~~
- [x] ~~EN error model для API validation/auth/rate-limit/scheduler.~~
- [x] ~~Retention: `RESULTS_MAX_FILES`, `RESULTS_MAX_AGE_DAYS`.~~
- [x] ~~UI: job polling + Scan History panel.~~
- [x] ~~README / `.env.example` / coverage source list обновлены.~~

### P1 — выполнить перед multi-user/public deployment

- [x] ~~SQLite persistence for jobs/schedules (single-node).~~ Job leases still open.
- [x] ~~Multi API tokens (`API_AUTH_TOKENS`) + per-token ownership of jobs/tasks/new results.~~
- [x] ~~`LEGACY_RESULTS_SHARED` flag to hide pre-ownership result files (default true).~~
- [x] ~~Target allowlist / engagement scopes (`TARGET_ALLOWLIST`, `TARGET_ALLOWLIST_FILE`).~~
- [x] ~~Named API keys + scopes (`API_AUTH_KEYS`, `read`/`scan`/`admin`, `/auth/whoami`).~~
- [x] ~~Optional Redis shared rate limits (`REDIS_URL`; memory fallback).~~
- [x] ~~Multi-worker job leases (SQLite claim + optional Redis fence + claim loop).~~
- [x] ~~Schedule multi-instance leader election (P1-03).~~
- [ ] Full multi-tenant RBAC / UI accounts (token isolation only today).
- [x] ~~Поднять `autonmap.py` coverage до ≥75% (~82%; overall ~78%; fail_under 75).~~
- [x] ~~CI browser E2E (Playwright dashboard smoke).~~
- [x] ~~axe-core a11y + keyboard/ARIA/320px regression in e2e.~~
- [x] ~~OpenAPI contract / route-parity tests.~~

### P2 — security и maintainability

- [x] ~~CSP without `'unsafe-inline'` via per-response nonces for dashboard HTML.~~
- [x] ~~Разделить liveness/readiness: `/live`, `/ready`, detailed `/health`.~~
- [x] ~~Pin Docker base image by digest.~~ (GitHub Actions digests still open)
- [x] ~~OpenAPI 3 schema at `/openapi.json` (plus human `/api/docs`).~~
- [x] ~~Retention для CLI `ai_reports` (`AI_REPORTS_MAX_DIRS` / `AI_REPORTS_MAX_AGE_DAYS`).~~
- [x] ~~Package boundary: `recon_operator/` (`server`, `auth`, `jobs`, `scheduler`, `api`, `config`) + `autonmap` shim.~~
- [ ] Further extract implementation out of `recon_operator/server.py` into leaf modules.
- [ ] Повторить GitNexus taint/PDG анализ после обновления index session.
- [ ] Generated contract tests from OpenAPI (optional next step).

### Release B — выполнено (2026-07-15)

- [x] ~~Rebrand → Recon Operator (UI/API/docs; multi-tool positioning).~~
- [x] ~~Profiles: Version, Safe, Vuln, Full + optional ports/scripts.~~
- [x] ~~`POST /results/import` (Nmap XML).~~
- [x] ~~`POST /results/diff` + UI Diff tab / Diff last two.~~
- [x] ~~Service stats bars in dashboard.~~

### Release C partial — выполнено

- [x] ~~Hybrid discovery: `Hybrid` / `HybridNaabu` / `HybridRustScan` + `discovery` field.~~
- [x] ~~SQLite persistence for jobs + scheduled tasks (`state_store.py`).~~

### Operator UX partial — выполнено

- [x] ~~Standalone CLI export for tool inventory (`python tool_inventory.py`).~~
- [x] ~~Timestamp of last refresh/scan and elapsed duration in dashboard.~~

### P3 — дальше

- [ ] Multi-user / scoped API keys.
- [x] ~~Redis for multi-worker rate limits.~~ (job leases still open; SQLite covers single-node durable state)
- [x] ~~Favicon/static asset caching after extracting inline UI assets.~~
- [ ] Optional locale switch.
- [ ] Rename GitHub repository path from `nmap-automator` → `recon-operator` (when ready).
- [ ] CI browser E2E + axe-core.
- [x] ~~Raise `autonmap.py` coverage toward ≥75%.~~

## 7. Журнал найденных проблем и решений

| ID | Приоритет | Область | Состояние | Наблюдение / решение |
| --- | --- | --- | --- | --- |
| ENV-001 | P1 | DevEx | Исправлено | Создана `.venv`; pins установлены; `pip check` pass |
| SEC-001 | P1 | CLI artifacts | Исправлено | Было `0644`; стало directory `0700`, files `0600`, atomic derived writes |
| UX-001 | P1 | Accessibility | Исправлено | Добавлены focus-visible, ARIA, labels и 44 px targets |
| UX-002 | P2 | Feedback | Исправлено | Action toast больше не заменяется `Dashboard refreshed` |
| UX-003 | P2 | Safety | Исправлено | Cancel требует confirm и имеет task-specific accessible name |
| UX-004 | P2 | Errors | Исправлено | UI показывает HTTP status; clipboard rejection обработан |
| CLI-001 | P2 | Decrypt | Исправлено | Wrong key/corrupt input теперь concise error, exit 1, без traceback |
| DEP-001 | P2 | Tooling | Исправлено | coverage `7.13.5 → 7.15.0`; остальные Python pins актуальны |
| CI-001 | P1 | CI runtime | Исправлено | checkout/setup-python обновлены до Node 24-compatible major v6 |
| ENV-002 | P2 | Docker | Ограничение среды | Docker daemon требует owner-approved privileged network setup; config/static audit pass |
| SEC-002 | P2 | CSP | Done | Static UI split + nonces/`'self'`; no `'unsafe-inline'` |
| ARC-001 | P1 | Scaling | Backlog | Tasks и limiter находятся в process memory; подходит только single worker/operator |

## 8. Команды финальной перепроверки

```bash
source .venv/bin/activate
ruff format --check .
ruff check .
python -m compileall -q .
coverage erase
coverage run -m unittest discover -v
coverage report
bandit -q -ll -r . -x ./.venv,./test_autonmap.py,./test_decrypt.py,./test_kali_ai_scan.py,./test_recon_planner.py,./test_tool_inventory.py
pip-audit -r requirements.txt
pip-audit -r requirements-dev.txt
API_AUTH_TOKEN=test-token FERNET_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= docker compose config --quiet
```
