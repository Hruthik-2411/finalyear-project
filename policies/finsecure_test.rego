# Run with:  opa test policies -v
package finsecure.authz_test

import rego.v1

import data.finsecure.authz

base := {"action": "tool_call", "role": "executor", "tool": "transfer_funds",
	"args": {"src": "ACC-1001", "dst": "ACC-1002", "amount": 5000},
	"resource": {"src_status": "ACTIVE", "dst_status": "ACTIVE", "daily_outflow": 0},
	"limits": {"single_txn_limit": 100000, "daily_limit": 200000}}

test_normal_transfer_allowed if {
	authz.decision.allow with input as base
}

test_researcher_cannot_transfer if {
	not authz.decision.allow with input as object.union(base, {"role": "researcher"})
}

test_frozen_source_denied if {
	not authz.decision.allow with input as object.union(base, {"resource": {"src_status": "FROZEN", "dst_status": "ACTIVE", "daily_outflow": 0}})
}

test_single_limit_denied if {
	not authz.decision.allow with input as object.union(base, {"args": {"src": "ACC-1001", "dst": "ACC-1002", "amount": 150000}})
}

test_daily_limit_denied if {
	not authz.decision.allow with input as object.union(base, {"resource": {"src_status": "ACTIVE", "dst_status": "ACTIVE", "daily_outflow": 198000}})
}

test_pii_in_case_note_denied if {
	not authz.decision.allow with input as {"action": "tool_call", "role": "executor", "tool": "add_case_note",
		"args": {"case_id": "FC-001", "note": "Contact: someone@mail.example"}, "resource": {}, "limits": {}}
}

test_bad_message_edge_denied if {
	not authz.decision.allow with input as {"action": "message", "role": "researcher", "receiver": "auditor"}
}

test_unfreeze_needs_approval if {
	d := authz.decision with input as {"action": "tool_call", "role": "executor", "tool": "unfreeze_account",
		"args": {"account_id": "ACC-1007"}, "resource": {}, "limits": {}}
	d.allow
	"human_approval" in d.obligations
}
