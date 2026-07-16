# Recon Operator — полный план улучшений

**Продукт:** Recon Operator (ранее Nmap Automator)  
**Текущая версия кода:** 1.8.4  
**Ветка:** `beta-hardening`  
**Дата плана:** 2026-07-16  
**Связанные файлы:** `AUDIT_CHECKLIST.md`, `README.md`, `SECURITY.md`

Этот документ — единый roadmap: что уже сделано, что осталось, в каком порядке, зачем, и как принимать «готово».

---

## 1. Видение продукта

**Recon Operator** — self-hosted control plane для **авторизованного** multi-tool recon:

| Слой | Роль |
| --- | --- |
| Engine | Nmap (subprocess + XML), optional hybrid discovery (Naabu / RustScan) |
| Control | Quart API, jobs, schedules, dashboard |
| Safety | API tokens, ownership, limits, CSP nonces, encrypted results |
| Intelligence | Kali inventory, review-only recon planner, AI-readable exports |
| Ops | Docker, probes, OpenAPI, SQLite state, retention |

**Не цель:** заменить Faraday/IVRE/SaaS pentest platforms; не auto-exec recon/exploit команд.

**Позиционирование:** best self-hosted **secure recon ops + AI handoff** tool для одного или нескольких операторов, не «ещё один bash nmap wrapper».

---

## 2. Текущее состояние (baseline 1.7.0)

### 2.1 Уже реализовано

#### Release A — One engine, durable results
- [x] Единый `scan_engine.py` (argv, без shell, без `python-nmap`)
- [x] Async jobs: `POST /scan` → 202, `GET/DELETE /jobs`, `?wait=1`
- [x] История: `GET /results`, `GET /results/<id>`
- [x] EN error model
- [x] Retention encrypted results (`RESULTS_MAX_FILES`, `RESULTS_MAX_AGE_DAYS`)
- [x] UI: job polling + Scan History

#### Release B — Operator complete (core)
- [x] Rebrand → **Recon Operator**
- [x] Profiles: Version, Safe, Vuln, Full + ports/scripts
- [x] XML import (`POST /results/import`)
- [x] Diff (`POST /results/diff` + UI)
- [x] Service stats bars

#### Release C — Hybrid + durable schedules
- [x] Hybrid discovery: Hybrid / HybridNaabu / HybridRustScan + `discovery`
- [x] SQLite (`state_store.py`, `STATE_DB_PATH`)
- [x] Восстановление schedules/jobs после restart

#### Platform hardening
- [x] Multi API tokens (`API_AUTH_TOKEN` + `API_AUTH_TOKENS`)
- [x] Per-token ownership jobs/tasks/new results
- [x] CSP nonces (без `unsafe-inline` на dashboard)
- [x] `/live`, `/ready`, `/health`
- [x] OpenAPI 3 (`/openapi.json`)
- [x] Inventory CLI (`python tool_inventory.py`)
- [x] Dashboard refresh/scan timestamps + duration
- [x] Docker base image pin by digest
- [x] CLI `ai_reports` retention

### 2.2 Метрики качества (ориентир)

| Метрика | Ориентир | Цель |
| --- | ---: | ---: |
| Unit tests | ~100 pass | ≥100, включая contract/E2E smoke |
| Coverage overall | ~78% (gate 75) | ≥75% ✓ |
| Coverage `autonmap.py` | ~82% | ≥75% ✓ |
| Ruff / Bandit / pip-audit | pass | pass + digest pins |
| Multi-worker | нет | Redis/queue optional |

### 2.3 Известные ограничения (by design сегодня)

1. **Не multi-tenant SaaS:** ownership = hash API-токена, нет users/roles UI.
2. **State single-node:** SQLite + process memory для rate-limit buckets; несколько workers не поддерживаются.
3. **Legacy results** без prefix `o{owner}_` видны любому auth-оператору.
4. **GitHub path** всё ещё `nmap-automator` (продукт уже Recon Operator).
5. **Planner never executes** — это feature, не баг.

---

## 3. Принципы улучшений

1. **Security by default** — loopback, auth, bounds, no shell, review-only planner.
2. **Nmap remains the depth scanner** — hybrid только discovery front-end.
3. **No auto-exploitation** — recon plan = suggestions only.
4. **Backward-compatible API** где возможно (`?wait=1`, legacy result files).
5. **Small focused PRs** — один смысловой инкремент = один merge.
6. **Перед правками символов** — impact analysis (GitNexus / code review blast radius).

---

## 4. Что нельзя / не стоит делать

| Не делать | Почему |
| --- | --- |
| Auto-run recon planner commands | Ломает threat model |
| Заменить Nmap masscan’ом как primary | Теряется service depth |
| Multi-tenant SaaS без redesign auth/storage | Высокий risk, другой продукт |
| Silent `rm -rf` / force-push / `--no-verify` | Опасно, против process |
| Хранить plaintext API results на диске | Нарушает security baseline |

---

## 5. Приоритеты и roadmap

### Легенда приоритетов

| Pri | Смысл |
| --- | --- |
| **P0** | Блокирует безопасную эксплуатацию / релизы |
| **P1** | Нужно до team / semi-public deploy |
| **P2** | Maintainability, security depth, DX |
| **P3** | Nice-to-have, polish, growth |

---

### 5.1 P0 — Release hygiene (короткий цикл)

| ID | Задача | Результат | Effort |
| --- | --- | --- | ---: |
| P0-01 | `git push` ветки `beta-hardening` | remote синхронизирован | S |
| P0-02 | Открыть PR → `main` с changelog 1.2–1.7 | reviewable release | S |
| P0-03 | Docker runtime smoke: `compose up`, `/live`, `/ready`, Ping scan | подтвердить container path | S |
| P0-04 | Обновить GitNexus index после merge | актуальный code graph | S |

**Статус 2026-07-16:** ~~P0-01 push~~ + ~~P0-02 PR~~ → https://github.com/hafych/nmap-automator/pull/10 (1.7.2). P0-03 Docker smoke / P0-04 reindex after merge.

**Критерий done:** PR green CI, compose health ok, README quick start воспроизводим.

---

### 5.2 P1 — Team-ready / semi-public

#### A. State & scale

| ID | Задача | Детали | Effort |
| --- | --- | --- | ---: |
| P1-01 | ~~Redis (или shared store) для rate limits~~ | `REDIS_URL` sliding window; memory fallback | M |
| P1-02 | ~~Job queue multi-worker~~ | SQLite lease + optional Redis fence + claim loop | L |
| P1-03 | ~~Schedule durability under multi-instance~~ | scheduler leader election (SQLite + Redis fence) | L |
| P1-04 | ~~Explicit target allowlist / engagement scopes~~ | `TARGET_ALLOWLIST` + `TARGET_ALLOWLIST_FILE` | M |

#### B. Identity & tenancy

| ID | Задача | Детали | Effort |
| --- | --- | --- | ---: |
| P1-05 | ~~Named API keys (id, label, created_at, revoked)~~ | `API_AUTH_KEYS` + `/auth/whoami` | M |
| P1-06 | ~~Key scopes: `scan`, `read`, `admin`~~ | hierarchy admin > scan > read | M |
| P1-07 | ~~UI: выбор/ротация ключа, label~~ | dashboard shows key label + scopes via whoami | S |
| P1-08 | ~~Hide legacy unowned results from multi-token deploys~~ | `LEGACY_RESULTS_SHARED` (default true; set false multi-token) | S |
| P1-09 | Optional user accounts (later) | password/OIDC — только если нужен team UI | XL |

#### C. Quality gates

| ID | Задача | Детали | Effort |
| --- | --- | --- | ---: |
| P1-10 | ~~Coverage `autonmap.py` ≥ 75%~~ | jobs, ownership, tools, planner, Telegram (~82%) | M |
| P1-11 | ~~Overall coverage ≥ 75%, fail_under поднять~~ | `fail_under = 75` in pyproject (~78%) | S |
| P1-12 | ~~Browser E2E в CI (Playwright)~~ | `e2e/` dashboard smoke + CI job | L |
| P1-13 | axe-core / accessibility regression | keyboard, ARIA, contrast | M |
| P1-14 | ~~OpenAPI contract tests~~ | route parity + schema shape (`test_openapi_contract.py`) | M |

**Критерий done P1:** 2+ API tokens с изоляцией; rate-limit корректный при 2 workers; coverage gate 75%; E2E smoke в CI.

---

### 5.3 P2 — Security, architecture, maintainability

| ID | Задача | Детали | Effort |
| --- | --- | --- | ---: |
| P2-01 | Разбить `autonmap.py` god-module | packages: `api/`, `auth/`, `jobs/`, `config/` | L |
| P2-02 | Static UI assets + cache headers | вынести CSS/JS из Python string | M |
| P2-03 | Favicon + static asset pipeline | | S |
| P2-04 | Pin GitHub Actions by SHA | Dependabot updates digests | S |
| P2-05 | Pin Compose image digests on publish | | S |
| P2-06 | Key rotation for Fernet (multi-key) | encrypt new, decrypt old | M |
| P2-07 | Audit log (who scanned what when) | append-only, no secrets | M |
| P2-08 | Trusted reverse-proxy mode | `X-Forwarded-For` opt-in, documented | S |
| P2-09 | GitNexus PDG/taint pass | security review automation | S |
| P2-10 | Structured logging (JSON optional) | correlation id per job | M |
| P2-11 | Metrics endpoint (Prometheus) | jobs active, scan duration, errors | M |
| P2-12 | Webhooks (Slack/Discord/generic) | richer than Telegram-only | M |
| P2-13 | Package as installable CLI | `recon-operator serve|scan|plan|inventory` | M |
| P2-14 | Entry rename / dual entry | keep `autonmap.py` alias | S |

**Критерий done P2:** модульная структура, static UI, digests pinned, audit trail, optional metrics.

---

### 5.4 P2/P3 — Product depth (competitiveness)

| ID | Задача | Конкурентный ответ | Effort |
| --- | --- | --- | ---: |
| PRD-01 | Named scan presets (Full/Safe/Vuln/Custom save) | Zenmap / 21y4z phases | M |
| PRD-02 | Custom NSE script packs (allow-list) | deeper recon | M |
| PRD-03 | Continuous monitoring alerts (diff → notify) | SaaS continuous | M |
| PRD-04 | Charts: ports/services over time | WebMap / Grafana | M |
| PRD-05 | Export PDF/HTML report | reporting tools | L |
| PRD-06 | Batch targets file upload | automation | S |
| PRD-07 | Progress streaming (SSE/WebSocket) | long scans UX | M |
| PRD-08 | Cancel running Nmap process tree | real cancel, not only job flag | M |
| PRD-09 | Import masscan/naabu JSON as discovery input | modern recon pipeline | M |
| PRD-10 | Optional Masscan front-end (like Hybrid) | speed at scale | M |
| PRD-11 | Locale RU/EN switch | mixed audience | M |
| PRD-12 | Dark theme / theme polish | UX | S |
| PRD-13 | Faraday / JSON export plugin | enterprise handoff | L |
| PRD-14 | Offline LLM analysis hook (optional) | AI niche, no auto-exec | L |

---

### 5.5 P3 — Growth & ops

| ID | Задача | Effort |
| --- | --- | ---: |
| P3-01 | Rename GitHub repo `nmap-automator` → `recon-operator` | S (+ comms) |
| P3-02 | GitHub release notes 1.7.0 + migration guide | S |
| P3-03 | Screenshots / assets in README | S |
| P3-04 | CONTRIBUTING expanded (architecture map) | S |
| P3-05 | SECURITY: threat model section | S |
| P3-06 | SBOM generation in CI | S |
| P3-07 | Signed container images (cosign optional) | M |
| P3-08 | Helm chart / K8s manifests | L |
| P3-09 | Homebrew / pipx install path | M |

---

## 6. Рекомендуемые релизы (последующие)

### Release D — «Ship & stabilize» (1 неделя)

1. ~~P0-01 push + P0-02 PR~~ — **done** ([PR #10](https://github.com/hafych/nmap-automator/pull/10)); P0-03 Docker smoke / P0-04 reindex still open  
2. ~~P1-10…P1-11 coverage~~ — **done** (autonmap ~82%, overall ~79%, fail_under 75)  
3. ~~P1-08 legacy results policy flag~~ — **done** (`LEGACY_RESULTS_SHARED`)  
4. ~~Changelog + migration notes~~ — **done** (README + §13 / SECURITY notes)  
5. ~~P1-04 target allowlist~~ — **done** (1.7.2)

**Ship:** 1.7.2 on PR #10 → `main` after CI + optional Docker smoke.

### Release E — «Team operators» (2–3 недели)

1. P1-05…P1-07 named keys + scopes  
2. P1-01 rate limits in Redis  
3. P1-04 target allowlist  
4. P1-12…P1-14 E2E + contract tests  

**Ship:** 1.8.0 multi-operator ready (still not SaaS multi-tenant).

### Release F — «Architecture cleanup» (2–4 недели)

1. P2-01 package split  
2. P2-02…P2-03 static UI  
3. P2-06…P2-08 rotation, audit, proxy  
4. P2-11 metrics  

**Ship:** 2.0.0 modular.

### Release G — «Depth & visibility» (ongoing)

1. PRD-03…PRD-08 monitoring, charts, progress, real cancel  
2. PRD-01 presets  
3. P3 branding/repo rename when ready  

---

## 7. Детальный backlog по областям

### 7.1 API

- [ ] Stable error schema `{ "error": "...", "code": "..." }`  
- [ ] Pagination for `/jobs`, `/results`  
- [ ] `GET /results` filter by target/date/owner  
- [ ] Soft-delete results  
- [ ] Job events stream (SSE)  
- [ ] OpenAPI → generated clients (optional)  

### 7.2 Scan engine

- [ ] Real process cancel (kill nmap pid group)  
- [ ] Per-scan resource accounting  
- [ ] IPv6 coverage tests  
- [ ] UDP hybrid path notes (privileges)  
- [ ] Profile validation matrix in tests  

### 7.3 Storage

- [ ] Result metadata index in SQLite (search without decrypt)  
- [ ] Optional encrypt result index fields  
- [ ] Backup/restore docs (FERNET_KEY + DB + volumes)  
- [ ] Vacuum/maintenance command  

### 7.4 UI

- [ ] Show owner/key label (not secret)  
- [ ] Job list panel (active + recent)  
- [ ] Diff picker (select two history items)  
- [ ] Import file picker (not only paste)  
- [ ] Mobile polish beyond 320px already tested  
- [ ] Optional offline PWA for last result  

### 7.5 Security

- [ ] Rate limit by token id, not only IP  
- [ ] Brute-force backoff on auth failures  
- [ ] Content-Type allow-list for import  
- [ ] Regular pip-audit in scheduled CI  
- [ ] Dependency review on PR  

### 7.6 DevEx / CI

- [ ] `make test` / `make lint` / `make docker`  
- [ ] Pre-commit hooks (ruff)  
- [ ] Matrix test with nmap mock only + optional real nmap  
- [ ] Coverage badge  

---

## 8. Миграции и breaking changes (учесть в релизах)

| Изменение | Impact | Mitigation |
| --- | --- | --- |
| `POST /scan` → 202 job (default) | clients expecting body hosts | `?wait=1` documented |
| Result filenames `o{owner}_…` | old scripts parsing names | regex updated; legacy files still decrypt |
| Task ids `o{owner}-target-type` | cancel scripts | return `task_id` from API |
| Product rename | bookmarks/docs | README note; repo rename later |
| Multi-token ownership | shared history split | one token = same behavior |

---

## 9. Definition of Done (общий)

Для каждой задачи из плана:

1. Код + тесты (unit и/или API)  
2. README / `.env.example` обновлены при user-facing change  
3. Ruff + unittest + Bandit green  
4. Нет HIGH/CRITICAL security regressions  
5. Ownership/auth paths не ослаблены  
6. Для API changes — OpenAPI и `/api/docs` синхронизированы  

Для релиза:

1. Changelog  
2. Version bump  
3. CI green on matrix  
4. Manual smoke: health, scan Ping localhost, history, plan  

---

## 10. Порядок работ «что делать прямо сейчас»

Рекомендуемый ближайший порядок (без перескока):

1. **P0** — push + PR + docker smoke  
2. **P1-10** — coverage sprint `autonmap.py`  
3. **P1-08** — flag для legacy results  
4. **P1-04** — target allowlist  
5. **P1-05/06** — named keys + scopes  
6. **P1-01** — Redis rate limits  
7. **P2-01** — module split  
8. **P3-01** — rename GitHub repo (когда пользователи готовы)

---

## 11. Карта файлов (куда класть изменения)

| Область | Файлы сейчас | Целевая структура (Release F) |
| --- | --- | --- |
| API entry | `autonmap.py` | `recon_operator/app.py` + routers |
| Engine | `scan_engine.py` | `recon_operator/engine/` |
| State | `state_store.py` | `recon_operator/state/` |
| UI | `ui.py` string | `recon_operator/static/` + templates |
| Inventory | `tool_inventory.py` | keep CLI + package |
| Planner | `recon_planner.py` | keep pure lib |
| CLI artifacts | `kali_ai_scan.py` | keep CLI module |
| Tests | `test_*.py` | `tests/` package |

`autonmap.py` / `alpha_autonmap.py` — compatibility shims.

---

## 12. Риски

| Риск | Вероятность | Impact | Mitigation |
| --- | --- | --- | --- |
| Multi-worker без Redis | high if scaled | duplicate scans | document single-worker; implement P1-01/02 |
| Fernet key loss | med | data unrecoverable | backup docs, multi-key rotation P2-06 |
| Repo rename breaks links | med | discoverability | redirects, dual badges |
| Hybrid tools missing | high on macOS | Hybrid fails clearly | already DiscoveryError; improve UI hint |
| Coverage pressure slows delivery | med | low velocity | raise fail_under stepwise 58→65→75 |

---

## 13. Журнал прогресса (обновлять)

| Дата | Версия | Что закрыто |
| --- | ---: | --- |
| 2026-07-15 | 1.2–1.4 | Engine unify, jobs, history, rebrand, hybrid, SQLite |
| 2026-07-15 | 1.5–1.6 | probes, OpenAPI, inventory CLI, multi-token, CSP nonces |
| 2026-07-15 | 1.7.0 | ownership, docker digest, ai_reports retention |
| 2026-07-16 | — | Этот план зафиксирован в `IMPROVEMENT_PLAN.md` |
| 2026-07-16 | 1.7.1 | Release D code: `LEGACY_RESULTS_SHARED`, coverage ≥75%, fail_under 75, migration notes |
| 2026-07-16 | 1.7.2 | P1-04 target allowlist (`TARGET_ALLOWLIST` / file), health flags |
| 2026-07-16 | 1.8.0 | P1-05/06/07 named API keys, scopes, whoami + dashboard key meta |
| 2026-07-16 | 1.8.1 | P1-01 optional Redis shared rate limits + owner-aware buckets |
| 2026-07-16 | 1.8.2 | P1-02 multi-worker job leases (SQLite claim, Redis fence, poller) |
| 2026-07-16 | 1.8.3 | P1-03 scheduler leader election; fix claim-path unit tests |
| 2026-07-16 | 1.8.4 | P1-12 Playwright e2e smoke CI; P1-14 OpenAPI contract tests |

---

## 14. Ссылки на исходный аудит

- Конкуренты (контекст): 21y4z nmapAutomator, WebMap, nmapwebui, nmap-ai, Faraday, IVRE, Zenmap, RustScan/Naabu  
- Дифференциаторы: encrypted results, review-only planner, Kali inventory, AI JSONL, hardened defaults  
- Пробелы vs best-in-class: async history (done), hybrid (done), persistence (partial), multi-worker (open), charts/monitoring (open)

---

*Документ живой: при закрытии пункта отмечать `[x]` здесь и/или в `AUDIT_CHECKLIST.md`, bump версии, короткая запись в §13.*
