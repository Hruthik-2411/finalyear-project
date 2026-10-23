# FinSecure authorisation policy (Open Policy Agent).
# Query:  POST /v1/data/finsecure/authz/decision   {"input": {...}}
# The Python fallback in backend/security/policy.py implements exactly these rules;
# tests/test_policy.py checks that both give the same answer.
package finsecure.authz

import rego.v1

read_tools := {"get_customer", "get_account", "get_transactions", "search_policy", "get_loan",
	"get_fraud_case", "read_customer_document", "list_fraud_cases"}

executor_tools := {"flag_fraud_case", "add_case_note", "freeze_account", "transfer_funds",
	"update_loan_status", "update_customer_contact", "unfreeze_account"}

role_tools := {
	"orchestrator": set(),
	"planner": set(),
	"researcher": read_tools,
	"executor": executor_tools,
	"auditor": read_tools | {"flag_for_review"},
}

allowed_edges := {
	["orchestrator", "planner"],
	["planner", "researcher"],
	["researcher", "executor"],
	["executor", "auditor"],
	["auditor", "orchestrator"],
}

# ---------------------------------------------------------------- RBAC
deny contains msg if {
	input.action == "tool_call"
	not input.tool in role_tools[input.role]
	msg := sprintf("RBAC: role '%s' may not use tool '%s'", [input.role, input.tool])
}

deny contains msg if {
	input.action == "message"
	not [input.role, input.receiver] in allowed_edges
	msg := sprintf("RBAC: '%s' may not send messages to '%s'", [input.role, input.receiver])
}

# ---------------------------------------------------------------- ABAC: transfers (POL-001/002/003)
deny contains "ABAC: source account is not ACTIVE (POL-002)" if {
	input.tool == "transfer_funds"
	input.resource.src_status != "ACTIVE"
}

deny contains "ABAC: destination account is not ACTIVE (POL-003)" if {
	input.tool == "transfer_funds"
	input.resource.dst_status != "ACTIVE"
}

deny contains "ABAC: source and destination are the same account" if {
	input.tool == "transfer_funds"
	upper(input.args.src) == upper(input.args.dst)
}

deny contains msg if {
	input.tool == "transfer_funds"
	to_number(input.args.amount) > input.limits.single_txn_limit
	msg := sprintf("ABAC: amount exceeds single-transaction limit of %v (POL-001)", [input.limits.single_txn_limit])
}

deny contains msg if {
	input.tool == "transfer_funds"
	input.resource.daily_outflow + to_number(input.args.amount) > input.limits.daily_limit
	msg := sprintf("ABAC: daily transfer limit of %v would be exceeded (POL-001)", [input.limits.daily_limit])
}

# ---------------------------------------------------------------- ABAC: loans (POL-008)
deny contains "ABAC: credit score below 650 cannot be approved (POL-008)" if {
	input.tool == "update_loan_status"
	upper(input.args.status) == "APPROVED"
	input.resource.credit_score < 650
}

deny contains "ABAC: a REJECTED loan can only be reconsidered on a fresh application (POL-008)" if {
	input.tool == "update_loan_status"
	upper(input.args.status) == "APPROVED"
	input.resource.loan_status == "REJECTED"
}

# ---------------------------------------------------------------- ABAC: data protection (POL-005)
deny contains "ABAC: personal data (email/phone) may not be written into case notes (POL-005)" if {
	input.tool in {"add_case_note", "flag_fraud_case", "flag_for_review"}
	text := concat(" ", [object.get(input.args, "note", ""), object.get(input.args, "reason", "")])
	regex.match(`[\w.+-]+@[\w-]+(\.[\w-]+)+|\+?\d[\d-]{9,}\d`, text)
}

# ---------------------------------------------------------------- obligations
obligations contains "human_approval" if {
	input.tool == "unfreeze_account"
}

obligations contains "human_approval" if {
	input.tool == "update_loan_status"
	upper(input.args.status) == "APPROVED"
	input.resource.loan_amount > 1000000
}

severity := "high" if {
	some msg in deny
	startswith(msg, "RBAC")
} else := "medium"

decision := {
	"allow": count(deny) == 0,
	"deny": sort([m | some m in deny]),
	"obligations": sort([o | some o in obligations]),
	"severity": severity,
}
