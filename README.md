# FinSecure: Zero-Trust Framework for Continuous Behavioural Security in Autonomous Multi-Agent Systems

FinSecure is a banking operations system run by five LLM agents (Orchestrator, Planner, Researcher,
Executor, Auditor, built with LangGraph). Every message between agents and every tool call goes
through one **Zero-Trust Gateway**, which checks it continuously, at every step and not just at login:

| # | Module | What it stops |
|---|--------|---------------|
| 1 | Identity (X.509 + RSA-PSS signatures) | Impersonation, forged or altered messages |
| 2 | Signed intent + delegation chain (provenance DAG) | Confused deputy: actions the user never asked for |
| 3 | Prompt Shield (Llama Prompt Guard 2 + LLM judge + spotlighting) | Prompt injection hidden in data |
| 4 | OPA policy engine (Rego, RBAC + ABAC) | Out-of-role tools, limit breaches, frozen accounts, PII leaks |
| 5 | Burst limiter | Behavioural bursts (rapid harvesting / draining) |
| 6 | Behavioural trust engine (non-linear, time-bounded recovery) | Reputation laundering |
| 7 | Decision engine (Approve / Restrict / Escalate / Block / Isolate) | Combines all of the above |
| 8 | Merkle audit ledger (signed roots outside the DB) | Audit tampering |

The same system runs in **Baseline** mode (Phase 1: the gateway only logs) and **Secured** mode, so
every attack can be shown succeeding and then failing.

---

## 1. What you need (Windows)

| Software | Why | Get it |
|----------|-----|--------|
| Python 3.10 or newer | Runs everything | python.org (tick **Add python.exe to PATH**) |
| Docker Desktop | Runs the real OPA policy server | docker.com (optional: a built-in evaluator with the same rules is used if OPA is not running) |
| Groq API key | The LLM | console.groq.com -> API Keys (free) |
| Node.js 18+ | Only if you edit the dashboard source | nodejs.org (the dashboard is already built in `frontend/dist`) |

## 2. Setup (once)

1. Unzip the project, e.g. to `C:\Projects\FinSecure`.
2. Double-click **`setup.bat`**. It creates `.venv`, installs the packages, creates `.env`, the
   database and the agents' certificates.
3. Open `.env` in Notepad and paste your key: `GROQ_API_KEY=gsk_...`
4. Start Docker Desktop, then double-click **`start_opa.bat`**.
5. Check everything: open a terminal in the folder and run
   ```
   .venv\Scripts\activate
   python run.py check
   ```
   You should see `GROQ_API_KEY set: True`, `OPA server: reachable`, `LangGraph: installed`, and an LLM test call.

## 3. Run

Double-click **`run.bat`**. The browser opens at **http://127.0.0.1:8000**.

* No internet at the venue? Use **`run_offline_demo.bat`** (offline mock LLM).
* Terminal alternative: `python run.py serve`, or `python run.py serve --provider mock`.

### Dashboard pages

| Page | Use it to show |
|------|----------------|
| Overview | Bank state, decisions so far, agent trust |
| Operations | Type a staff request. Shows the answer, the signed intent and the checkpoint strip for every envelope |
| Bank data | Accounts, transactions, loans, fraud cases, policies (watch attacks change them) |
| Pending reviews | Irreversible actions held for a human (approve/reject) |
| Security console | Live stream of gateway decisions and alerts |
| Delegation graph | The provenance DAG of a run, coloured by verdict |
| Trust monitor | Trust per agent over time, with thresholds |
| Audit trail | Merkle ledger, signed roots, **Tamper** and **Verify** buttons, compliance report |
| Attack lab | Each attack class, run on Baseline and Secured side by side |
| Results | Evaluation tables and charts |
| Settings | Switch LLM provider and turn individual security modules on/off |

The **Secured / Baseline** switch at the top changes mode instantly. **Reset environment** restores
the original data.

## 4. Suggested 12-minute demo

1. **Operations -> Make transfer.** Walk through the signed intent (operation, entities, max amount)
   and the checkpoint strip: every envelope passes Identity, Chain, Intent scope, OPA, Shield, Burst, Trust.
2. **Attack lab -> Prompt injection.** Baseline: Rs 35,000 goes to ACC-9999. Secured: the Shield
   redacts the memo and the intent check blocks the transfer.
3. **Attack lab -> Confused deputy.** A harmless policy question ends in `transfer_funds` on Baseline.
   Secured: blocked because the signed intent says `policy_query, no writes`. Open **Delegation graph**.
4. **Attack lab -> Reputation laundering.** Compare our trust curve with the linear one: 40 cheap actions
   push the linear score back above 0.7, while ours stays under the time-based ceiling and the transfer is blocked.
5. **Attack lab -> Behavioural burst.** On Secured the burst is stopped at request 21, and repeated violations isolate the Researcher.
6. **Audit trail -> Tamper with a row -> Verify ledger.** The exact edited event is reported.
7. **Attack lab -> Impersonation.** A certificate from a rogue CA is rejected.
8. **Results.** Attack success baseline vs secured, false positives, utility, ablation, latency.

Have a backup: record a screen video the day before, and keep `run_offline_demo.bat` ready.

## 5. Evaluation

```
run_eval.bat                  quick: 14 benign tasks + 40 attack runs + 6 scenarios, Baseline and Secured
run_eval.bat --ablation       also "without X" and "only X" for each module
run_eval.bat --full           all 40 benign tasks and 380 attack runs per configuration
python run.py eval --provider mock --full --ablation    the offline worst-case model, takes a few minutes
```

Results go to `results/` (`.jsonl` raw rows, `_summary.json`, `.md` table, PNG charts) and appear on
the **Results** page.

* **Benchmark design** (AgentDojo-style): 40 user tasks in 11 categories, each with a programmatic
  success check. 10 attacker goals, each with a programmatic "attack succeeded" check. 5 injection
  points (transaction memo, policy KB, loan application text, fraud reporter notes, customer
  documents). An attack run = user task x attacker goal, planted where that task reads.
* **Metrics:** benign utility, false-positive rate, utility under attack (with and without human
  approval), attack success rate per goal / injection point, latency p50/p95, LLM calls per run.
* **Groq free tier:** a quick run makes roughly 1,500 LLM calls. Rate limits are retried
  automatically, so it simply takes longer (often 30-60 min). Run `--full` overnight or use Ollama.
* **Mock results** (shipped in `results/`) use the offline model that *always* obeys injected text,
  a worst case. Report Groq numbers as your main results and mock numbers as the worst case.

## 6. Tests

`run_tests.bat` (or `python run.py test`) runs 15 offline tests: signatures, certificates, revocation,
Merkle proofs, the trust formula properties, OPA rules (and that OPA and the Python fallback agree when
OPA is running), the intent scope, end-to-end attacks in both modes, and the API. You can also run the
policy unit tests with OPA itself: `docker run --rm -v %cd%\policies:/p openpolicyagent/opa:0.70.0 test /p -v`.

## 7. Configuration (`config.yaml`)

* `llm.provider`: `groq` | `ollama` | `mock`. `llm.groq_model`: change it if Groq retires the model
  (see console.groq.com/docs/models). `fallback_to_ollama`: use local Ollama if Groq fails.
* `security.mode`: `secured` | `baseline`. `security.modules`: turn modules off.
* `trust`: initial score, eta0, window W, tau, action weights, severities, thresholds.
* `burst`, `audit.batch_size`, `banking` limits (single Rs 1,00,000; daily Rs 2,00,000).

## 8. Command reference

```
python run.py setup | serve | check | test | reset
python run.py ask "Transfer Rs 25,000 from ACC-1002 to ACC-1012"
python run.py scenario prompt_injection|confused_deputy|reputation_laundering|behavioural_burst|audit_tampering|impersonation
python run.py eval [--quick|--full] [--ablation] [--configs baseline,secured] [--suite benign|attack|scenarios|all]
python run.py tamper   then   python run.py verify
Add --provider mock|groq|ollama or --mode baseline|secured to any command.
```

## 9. Project structure

```
backend/
  app.py                FastAPI: REST API, WebSocket events, serves the dashboard
  config.py             config.yaml + .env
  agents/workflow.py    the 5 LangGraph agents
  gateway/              envelope.py (signed message format), gateway.py (the choke point)
  security/             identity, intent, provenance, shield, policy, behaviour (burst+trust+anomaly),
                        decision, audit (Merkle), report
  llm/                  provider.py (Groq/Ollama/Mock), prompts.py, mock.py
  tools/                banking_tools.py (16 tools), registry.py
  db/                   models.py, seed.py (deterministic synthetic data), database.py
policies/               finsecure.rego + finsecure_test.rego (OPA)
benchmark/              tasks.py, inject.py, scenarios.py, runner.py, analyze.py
frontend/               React dashboard (src/ = source, dist/ = built)
tests/                  automated tests
results/                evaluation output
data/                   created at runtime: SQLite DB, certificates, ledger roots
```

## 10. Troubleshooting

| Problem | Fix |
|---------|-----|
| `GROQ_API_KEY is not set` | Put the key in `.env` (not `.env.example`) and restart |
| Groq `model_decommissioned` / 404 | Change `llm.groq_model` in `config.yaml` to a current model |
| Groq 429 rate limit | It retries automatically; for long evaluations use `--quick` or Ollama |
| `OPA: built-in` in the top bar | Docker Desktop not running or `start_opa.bat` not run. The built-in evaluator applies the same rules |
| Port 8000 in use | Change `server.port` in `config.yaml` |
| Want to start fresh | `python run.py reset` or the **Reset environment** button |
| Changed the dashboard source | `cd frontend && npm install && npm run build` |
