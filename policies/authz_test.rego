# Unit tests for the authorization policy.  Run:  opa test policies/ -v
package finguard.authz_test

import data.finguard.authz

customer := {"user": "alice", "role": "customer", "mfa": true}

transfer(subject, ctx) := {
	"subject": subject,
	"action": "transaction.transfer",
	"resource": {"owner": "alice", "account": "ZT1"},
	"context": object.union({"caller": "transaction", "amount": 1000, "risk_level": "low", "device_trust": "trusted"}, ctx),
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

test_transfer_from_pending_device_denied if {
	d := authz.decision with input as transfer(customer, {"device_trust": "pending"})
	not d.allow
	"device_not_trusted" in d.reasons
}

test_transfer_without_device_info_fails_closed if {
	inp := transfer(customer, {})
	no_device := object.union(object.remove(inp, ["context"]), {"context": object.remove(inp.context, ["device_trust"])})
	d := authz.decision with input as no_device
	"device_not_trusted" in d.reasons
}

test_step_up_cannot_bypass_untrusted_device if {
	d := authz.decision with input as transfer(customer, {"device_trust": "pending", "risk_level": "medium", "step_up": true})
	not d.allow
	"device_not_trusted" in d.reasons
}

test_every_role_manages_own_sessions_and_devices if {
	every r in ["customer", "teller", "admin"] {
		d := authz.decision with input as {
			"subject": {"user": "u", "role": r, "mfa": true},
			"action": "self.manage", "resource": {}, "context": {"caller": "gateway"},
		}
		d.allow
	}
}

test_only_admin_sets_session_policy_or_quarantines if {
	every a in ["admin.session_policy", "admin.quarantine", "admin.devices"] {
		c := authz.decision with input as {"subject": customer, "action": a, "resource": {}, "context": {"caller": "gateway"}}
		not c.allow
		ad := authz.decision with input as {
			"subject": {"user": "admin", "role": "admin", "mfa": true},
			"action": a, "resource": {}, "context": {"caller": "gateway"},
		}
		ad.allow
	}
}

test_only_admin_searches_and_controls_users if {
	every a in ["admin.search", "admin.user_control"] {
		authz.decision.allow with input as {
			"subject": {"user": "admin", "role": "admin", "mfa": true},
			"action": a, "resource": {}, "context": {"caller": "gateway"},
		}
		every r in ["customer", "teller"] {
			not authz.decision.allow with input as {
				"subject": {"user": "x", "role": r, "mfa": true},
				"action": a, "resource": {}, "context": {"caller": "gateway"},
			}
		}
	}
}

test_admin_search_from_unknown_workload_denied if {
	d := authz.decision with input as {
		"subject": {"user": "admin", "role": "admin", "mfa": true},
		"action": "admin.search", "resource": {}, "context": {"caller": "transaction"},
	}
	"untrusted_workload" in d.reasons
}
