# AI handoff (low-token packs)

Recon Operator already stores **full-fidelity** encrypted scan results.  
For LLMs and agents, **do not paste full `/results/<id>` JSON** into chat.

## Prefer `/ai/pack`

Default response is a **small** NDJSON pack (`budget=s`):

- host + **open** services only (closed ports omitted)
- compact findings
- next-step / missing-tool signals (from the review-only planner)
- short defense hints
- hard cap: **≤ 4 KiB or ≤ 100 lines**

```bash
# From a posted scan object
curl -sS -X POST "http://127.0.0.1:5000/ai/pack?budget=s" \
  -H "X-API-KEY: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @scan_result.json

# From a stored result or completed job
curl -sS -H "X-API-KEY: $API_TOKEN" \
  "http://127.0.0.1:5000/ai/pack?result_id=<filename>&budget=s"

curl -sS -H "X-API-KEY: $API_TOKEN" \
  "http://127.0.0.1:5000/ai/pack?job_id=<uuid>&budget=m&format=json"
```

### Budgets

| Budget | Use |
| --- | --- |
| `s` (default) | One LLM turn / brief (hard cap ≤4 KiB and ≤100 lines) |
| `m` | Session context (more next/gap/defense/inv rows; still no closed-port noise) |
| `l` or `detail=full` | Larger pack when needed; full archive remains `GET /results/<id>` |

### Line types (`t`)

`meta`, `host`, `svc`, `finding`, `next`, `gap`, `inv`, `defense`, `ask`, `posture`, `drift`,
and for retest: `diff`, `change`

Schema: `recon-ai-pack/v1`.

Offline packs accept either **operator** results (`protocols` map) or **`ai-nmap-report/v1`**
hosts (`ports` list) via `scan_engine.ensure_operator_result`.

### Expected posture (defense verification)

Set `EXPECTED_POSTURE` / `EXPECTED_POSTURE_FILE` or POST to `/posture/evaluate`:

```json
{"deny_unexpected": true, "services": [{"port": 22, "proto": "tcp", "name": "ssh"}]}
```

Drift rows appear in AI packs automatically when posture is configured.

### Retest (baseline vs current)

```bash
curl -sS -X POST "http://127.0.0.1:5000/ai/pack?mode=retest&budget=s" \
  -H "X-API-KEY: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"baseline":{...},"scan":{...}}'
```

Offline CLI (no server):

```bash
python -m recon_operator pack current.json --budget s
python -m recon_operator pack current.json --baseline baseline.json --budget s
python -m recon_operator presets
```

### Engagement presets

```bash
curl -sS -H "X-API-KEY: $API_TOKEN" http://127.0.0.1:5000/presets
curl -sS -X POST http://127.0.0.1:5000/scan \
  -H "X-API-KEY: $API_TOKEN" -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","preset":"map"}'
```

Ordered phases: `discovery` → `map` → `safe` (plus `depth` / `vuln` / `hybrid`).

### Playbook chain (sequential jobs)

```bash
# Start standard chain (discovery → map → safe)
curl -sS -X POST http://127.0.0.1:5000/playbook/run \
  -H "X-API-KEY: $API_TOKEN" -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","playbook":"standard"}'
# -> 202 { engagement_id, steps:[{phase,job_id,status}...] }

curl -sS -H "X-API-KEY: $API_TOKEN" \
  http://127.0.0.1:5000/playbook/<engagement_id>
```

Playbooks: `standard`, `quick` (discovery→map), `deep` (…→depth).  
Custom: `{"target":"...","phases":["discovery","map"]}`.

## Agent rules (short)

1. Call **one** `/ai/pack` per turn when possible.  
2. Never put API tokens or Fernet keys into the model context.  
3. Treat `next` as **operator-reviewed** suggestions only (no auto-exec).  
4. Escalate to full result only if the pack meta marks truncation and deep analysis is required.

## Related surfaces

| Endpoint | Role |
| --- | --- |
| `GET /tools/ai-context` | Inventory context (jsonl/md) |
| `POST /recon/plan` | Full review-only plan |
| `GET /results/<id>` | Full fidelity archive (encrypted storage) |
| `GET /ai/pack` | **Default AI path** |
