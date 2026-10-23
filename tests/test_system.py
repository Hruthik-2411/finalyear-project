"""End-to-end tests with the mock LLM: workflow, attacks, scenarios and the API."""
from backend.config import get_config
from backend.db.database import session_scope
from backend.db.models import Account
from backend.db.seed import reset_database
from backend.gateway.gateway import gateway


def _fresh(mode="secured"):
    get_config()["security"]["mode"] = mode
    get_config()["security"]["modules"] = {m: True for m in ("identity", "intent", "shield", "policy", "burst", "trust")}
    reset_database()
    gateway().reset()


def _bal(acc):
    with session_scope() as s:
        return s.get(Account, acc).balance


def test_benign_transfer_is_approved():
    from backend.agents.workflow import run_request

    _fresh()
    before = _bal("ACC-1002")
    r = run_request("Transfer Rs 25,000 from ACC-1002 to ACC-1012 as requested by the customer.")
    assert r["status"] == "completed"
    assert _bal("ACC-1002") == before - 25000
    assert all(t["verdict"] in ("APPROVE", "ISSUED") for t in r["trace"])


def test_injection_baseline_vs_secured():
    from benchmark.inject import plant
    from benchmark.runner import run_one
    from benchmark.tasks import INJECTION_TASKS, USER_TASKS

    task, inj = USER_TASKS[0], INJECTION_TASKS[0]
    _fresh("baseline")
    assert run_one(task, inj)["attack_success"] is True
    _fresh("secured")
    row = run_one(task, inj)
    assert row["attack_success"] is False and row["user_success"] is True


def test_scenarios_secured():
    from benchmark.scenarios import SCENARIOS, run_scenario

    _fresh("secured")
    for name in SCENARIOS:
        assert run_scenario(name)["attack_succeeded"] is False, name


def test_scenarios_baseline():
    from benchmark.scenarios import run_scenario

    _fresh("baseline")
    for name in ("prompt_injection", "confused_deputy", "impersonation", "audit_tampering"):
        assert run_scenario(name)["attack_succeeded"] is True, name
    _fresh("secured")


def test_api_smoke():
    from fastapi.testclient import TestClient

    from backend.app import app

    _fresh()
    c = TestClient(app)
    assert c.post("/api/reset").json()["ok"]
    r = c.post("/api/run", json={"request": "What is the current balance and status of account ACC-1012?"}).json()
    assert r["status"] == "completed" and "40046" in r["final"].replace(",", "")
    assert len(c.get(f"/api/dag/{r['run_id']}").json()["nodes"]) >= 6
    assert c.post("/api/audit/verify").json()["ok"]
    assert c.post("/api/audit/tamper").status_code == 200
    assert not c.post("/api/audit/verify").json()["ok"]
