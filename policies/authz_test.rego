# Unit tests for the authorization policy.  Run:  opa test policies/ -v
package finguard.authz_test

import data.finguard.authz

customer := {"user": "alice", "role": "customer", "mfa": true}

transfer(subject, ctx) := {
	"subject": subject,
	"action": "transaction.transfer",
	"resource": {"owner": "alice", "account": "ZT1"},
	"context": object.union({"caller": "transaction", "amount": 1000, "risk_level": "low"}, ctx),
}

test_low_risk_own_transfer_allowed if {
	d := authz.decision with input as transfer(customer, {})
	d.allow
	not d.step_up
}

test_medium_risk_requires_step_up if {
	d := authz.decision with input as transfer(customer, {"risk_level": "medium"})
	not d.allow
	d.step_up
	"step_up_required" in d.reasons
}

test_medium_risk_after_step_up_allowed if {
	d := authz.decision with input as transfer(customer, {"risk_level": "medium", "step_up": true})
	d.allow
}

test_high_risk_denied_even_with_step_up if {
	d := authz.decision with input as transfer(customer, {"risk_level": "high", "step_up": true})
	not d.allow
	"risk_too_high" in d.reasons
}

test_missing_risk_fails_closed if {
	d := authz.decision with input as transfer(customer, {"risk_level": null})
	not d.allow
	"risk_unknown" in d.reasons
}

test_over_limit_denied if {
	d := authz.decision with input as transfer(customer, {"amount": 500000})
	"amount_over_limit" in d.reasons
}

test_no_mfa_denied if {
	d := authz.decision with input as transfer({"user": "alice", "role": "customer", "mfa": false}, {})
	"mfa_required" in d.reasons
}

test_transfer_from_someone_elses_account_denied if {
	inp := object.union(transfer(customer, {}), {"resource": {"owner": "bob", "account": "ZT2"}})
	d := authz.decision with input as inp
	"role_not_permitted" in d.reasons
}

test_wrong_workload_denied if {
	d := authz.decision with input as transfer(customer, {"caller": "account"})
	"untrusted_workload" in d.reasons
}

test_admin_cannot_move_money if {
	d := authz.decision with input as transfer({"user": "admin", "role": "admin", "mfa": true}, {})
	"role_not_permitted" in d.reasons
}

test_teller_reads_any_account if {
	d := authz.decision with input as {
		"subject": {"user": "teller", "role": "teller", "mfa": true},
		"action": "account.read",
		"resource": {"owner": "bob"},
		"context": {"caller": "account"},
	}
	d.allow
}

test_teller_cannot_transfer if {
	d := authz.decision with input as transfer({"user": "teller", "role": "teller", "mfa": true}, {})
	"role_not_permitted" in d.reasons
}

test_customer_cannot_open_dashboard if {
	d := authz.decision with input as {
		"subject": customer,
		"action": "admin.dashboard",
		"resource": {},
		"context": {"caller": "gateway"},
	}
	not d.allow
}

test_admin_dashboard_allowed if {
	d := authz.decision with input as {
		"subject": {"user": "admin", "role": "admin", "mfa": true},
		"action": "admin.dashboard",
		"resource": {},
		"context": {"caller": "gateway"},
	}
	d.allow
}
