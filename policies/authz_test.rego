# Unit tests for the authorization policy.  Run:  opa test policies/ -v
package finguard.authz_test

import data.finguard.authz

customer := {"user": "alice", "role": "customer", "mfa": true}

transfer(subject, ctx) := {
	"subject": subject,
	"action": "transaction.transfer",
	"resource": {"owner": "alice", "account": "ZT1"},
	"context": object.union(
		{
			"caller": "transaction", "amount": 1000, "risk_level": "low", "device_trust": "trusted",
			"sender_status": "active", "receiver_status": "active", "daily_used": 0, "daily_limit": 100000, "outgoing_enabled": true,
		},
		ctx,
	),
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
	every a in ["admin.search", "admin.user_control", "admin.fraud", "admin.containers", "admin.threats", "admin.network", "admin.policy", "admin.settings"] {
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

# ------------------------------------------------- module 3: banking rules
test_frozen_accounts_cannot_send_or_receive if {
	"account_frozen" in authz.decision.reasons with input as transfer(customer, {"sender_status": "frozen"})
	"payee_account_frozen" in authz.decision.reasons with input as transfer(customer, {"receiver_status": "frozen"})
}

test_missing_account_status_denies if {
	inp := transfer(customer, {})
	no_status := object.union(object.remove(inp, ["context"]), {"context": object.remove(inp.context, ["sender_status"])})
	"account_frozen" in authz.decision.reasons with input as no_status
}

test_daily_limit_enforced_and_fails_closed if {
	"daily_limit_exceeded" in authz.decision.reasons with input as transfer(customer, {"daily_used": 99500, "amount": 1000})
	inp := transfer(customer, {})
	no_limit := object.union(object.remove(inp, ["context"]), {"context": object.remove(inp.context, ["daily_limit"])})
	"daily_limit_exceeded" in authz.decision.reasons with input as no_limit
}

test_high_value_needs_approval_but_is_allowed if {
	d := authz.decision with input as transfer(customer, {"amount": 60000})
	d.allow
	d.needs_approval
	not authz.decision.needs_approval with input as transfer(customer, {"amount": 49999})
}

test_operations_cannot_transfer_or_use_admin_tools if {
	ops := {"user": "ops", "role": "operations", "mfa": true}
	not authz.decision.allow with input as transfer(ops, {})
	not authz.decision.allow with input as {"subject": ops, "action": "admin.dashboard", "resource": {}, "context": {"caller": "gateway"}}
	authz.decision.allow with input as {"subject": ops, "action": "ops.approve", "resource": {}, "context": {"caller": "transaction"}}
	not authz.decision.allow with input as {"subject": customer, "action": "ops.approve", "resource": {}, "context": {"caller": "transaction"}}
	not authz.decision.allow with input as {"subject": {"user": "admin", "role": "admin", "mfa": true}, "action": "ops.accounts", "resource": {}, "context": {"caller": "account"}}
}

test_customer_cancels_only_own if {
	authz.decision.allow with input as {
		"subject": customer, "action": "transaction.cancel",
		"resource": {"owner": "alice"}, "context": {"caller": "transaction"},
	}
	not authz.decision.allow with input as {
		"subject": customer, "action": "transaction.cancel",
		"resource": {"owner": "bob"}, "context": {"caller": "transaction"},
	}
}

# ------------------------------------------------ module 8: safe policy editor
test_policy_data_can_lower_but_never_raise_limits if {
	low := {"transfer_limit_customer": 10000, "high_value_threshold": 5000}
	"amount_over_limit" in authz.decision.reasons with input as transfer(customer, {"amount": 20000})
		with data.zt_policy as low
	authz.decision.needs_approval with input as transfer(customer, {"amount": 6000}) with data.zt_policy as low
	high := {"transfer_limit_customer": 9999999, "high_value_threshold": 9999999}
	"amount_over_limit" in authz.decision.reasons with input as transfer(customer, {"amount": 250000})
		with data.zt_policy as high
	authz.decision.needs_approval with input as transfer(customer, {"amount": 60000}) with data.zt_policy as high
}

test_medium_risk_can_be_made_to_deny if {
	d := authz.decision with input as transfer(customer, {"risk_level": "medium", "step_up": true})
		with data.zt_policy as {"medium_risk_action": "deny"}
	not d.allow
	"medium_risk_denied_by_policy" in d.reasons
}

test_custom_deny_rules_add_denials_only if {
	rules := {"custom_denies": [{"id": "r1", "role": "teller", "action": "account.read"}]}
	teller := {"user": "t", "role": "teller", "mfa": true}
	inp := {"subject": teller, "action": "account.read", "resource": {"owner": "alice"}, "context": {"caller": "account"}}
	authz.decision.allow with input as inp
	"custom_rule:r1" in authz.decision.reasons with input as inp with data.zt_policy as rules
}

test_custom_rules_cannot_lock_the_policy_editor if {
	admin := {"user": "admin", "role": "admin", "mfa": true}
	rules := {"custom_denies": [{"id": "x", "role": "*", "action": "admin.policy"}]}
	authz.decision.allow with input as {"subject": admin, "action": "admin.policy", "resource": {}, "context": {"caller": "gateway"}}
		with data.zt_policy as rules
}

test_corrupt_policy_data_stops_transfers if {
	d := authz.decision with input as transfer(customer, {}) with data.zt_policy as {"transfer_limit_customer": "lots"}
	not d.allow
	"policy_config_invalid" in d.reasons
}

test_simulation_uses_candidate_without_changing_live if {
	inp := object.union(transfer(customer, {"amount": 20000}), {"policy": {"transfer_limit_customer": 10000}})
	"amount_over_limit" in authz.simulate.reasons with input as inp
	authz.decision.allow with input as inp
}

# ------------------------------------------------ customer portal
test_customer_can_switch_off_own_transfers_fail_closed if {
	"transfers_disabled_by_customer" in authz.decision.reasons with input as transfer(customer, {"outgoing_enabled": false})
	inp := transfer(customer, {})
	missing := object.union(object.remove(inp, ["context"]), {"context": object.remove(inp.context, ["outgoing_enabled"])})
	"transfers_disabled_by_customer" in authz.decision.reasons with input as missing
}

test_support_tickets_own_only_and_ops_manage if {
	authz.decision.allow with input as {"subject": customer, "action": "support.ticket", "resource": {"owner": "alice"}, "context": {"caller": "account"}}
	not authz.decision.allow with input as {"subject": customer, "action": "support.ticket", "resource": {"owner": "bob"}, "context": {"caller": "account"}}
	ops := {"user": "ops", "role": "operations", "mfa": true}
	authz.decision.allow with input as {"subject": ops, "action": "support.manage", "resource": {}, "context": {"caller": "account"}}
	admin := {"user": "admin", "role": "admin", "mfa": true}
	not authz.decision.allow with input as {"subject": admin, "action": "support.manage", "resource": {}, "context": {"caller": "account"}}
}

# ------------------------------------------------ teller portal
teller := {"user": "teller", "role": "teller", "mfa": true}

branch(action, ctx) := {
	"subject": teller,
	"action": action,
	"resource": {"owner": "alice", "account": "ZT1"},
	"context": object.union(
		{
			"caller": "transaction", "amount": 5000, "risk_level": "low", "device_trust": "trusted",
			"sender_status": "active", "receiver_status": "active", "daily_used": 0, "daily_limit": 100000,
			"outgoing_enabled": true, "verification": "sms+totp",
		},
		ctx,
	),
}

test_counter_withdrawal_needs_sms_and_authenticator if {
	authz.decision.allow with input as branch("branch.withdraw", {})
	"customer_not_verified" in authz.decision.reasons with input as branch("branch.withdraw", {"verification": "sms"})
	"customer_not_verified" in authz.decision.reasons with input as branch("branch.transfer", {"verification": null})
	authz.decision.allow with input as branch("branch.deposit", {"verification": null})
}

test_counter_money_needs_teller_on_trusted_device if {
	"device_not_trusted" in authz.decision.reasons with input as branch("branch.deposit", {"device_trust": "pending"})
}

test_counter_rules_reuse_banking_policy if {
	"account_frozen" in authz.decision.reasons with input as branch("branch.withdraw", {"sender_status": "frozen"})
	"daily_limit_exceeded" in authz.decision.reasons with input as branch("branch.withdraw", {"daily_used": 99000})
	"amount_over_limit" in authz.decision.reasons with input as branch("branch.withdraw", {"amount": 250000})
	authz.decision.needs_approval with input as branch("branch.withdraw", {"amount": 60000})
	not authz.decision.needs_approval with input as branch("branch.deposit", {"amount": 60000})
	authz.decision.needs_approval with input as branch("branch.deposit", {"amount": 250000})
}

customer_cannot_do_counter_work if {
	not authz.decision.allow with input as object.union(branch("branch.deposit", {}), {"subject": customer})
}

test_customers_and_admins_cannot_use_the_counter if {
	customer_cannot_do_counter_work
	admin := {"user": "admin", "role": "admin", "mfa": true}
	not authz.decision.allow with input as object.union(branch("branch.withdraw", {}), {"subject": admin})
}

approval(subject, ctx) := {
	"subject": subject,
	"action": "ops.approve",
	"resource": {},
	"context": object.union(
		{
			"caller": "transaction", "amount": 60000, "risk_level": "low",
			"initiator": "alice", "owner": "alice", "prior_approvers": [],
		},
		ctx,
	),
}

test_dual_control_and_maker_checker if {
	authz.decision.allow with input as approval(teller, {})
	authz.decision.approvals_required == 1 with input as approval(teller, {})
	authz.decision.approvals_required == 2 with input as approval(teller, {"amount": 150000})
	authz.decision.approvals_required == 2 with input as approval(teller, {"risk_level": "medium"})
	"maker_cannot_approve" in authz.decision.reasons with input as approval(teller, {"initiator": "teller"})
	"already_approved_by_you" in authz.decision.reasons with input as approval(teller, {"prior_approvers": ["teller"]})
	ops := {"user": "ops", "role": "operations", "mfa": true}
	authz.decision.allow with input as approval(ops, {"prior_approvers": ["teller"]})
}
