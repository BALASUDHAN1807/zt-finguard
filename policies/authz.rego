# ZT-FinGuard authorization policy (policy-as-code).
#
# Evaluated on EVERY request by the service that owns the resource.
# Query: POST /v1/data/finguard/authz/decision  {"input": {...}}
#
# input = {
#   "subject":  {"user": "alice", "role": "customer", "mfa": true},
#   "action":   "transaction.transfer",
#   "resource": {"owner": "alice", "account": "ZT1000000002"},
#   "context":  {"caller": "transaction", "amount": 2500,
#                "risk_level": "low|medium|high", "step_up": false,
#                "device_trust": "trusted|pending",
#                "sender_status": "active|frozen", "receiver_status": "active|frozen",
#                "daily_used": 12000, "daily_limit": 100000}
# }
#
# result = {"allow": bool, "step_up": bool, "needs_approval": bool, "reasons": [..]}
package finguard.authz

# ---------------------------------------------------------------- role model
# ":own"  -> only on resources the subject owns
# ":any"  -> on any resource
# plain   -> no resource owner involved
permissions := {
	"customer": {
		"account.read:own",
		"transaction.transfer:own",
		"transaction.history:own",
		"transaction.cancel:own",
		"beneficiary.manage:own",
		"self.manage",
	},
	# Banking operations (maker-checker). Cannot move its own money (has no account),
	# cannot touch security tooling, and the customer still initiates every transfer.
	"operations": {
		"ops.accounts",
		"ops.transactions",
		"ops.freeze",
		"ops.limits",
		"ops.approve",
		"account.read:any",
		"transaction.history:any",
		"transaction.cancel:any",
		"self.manage",
	},
	"teller": {
		"account.read:any",
		"transaction.history:any",
		"self.manage",
	},
	# Separation of duties: admins run security tooling but can never
	# move money or read customer balances.
	"admin": {
		"admin.dashboard",
		"admin.audit",
		"admin.session_policy",
		"admin.devices",
		"admin.quarantine",
		"admin.search",
		"admin.user_control",
		"admin.fraud",
		"admin.containers",
		"admin.threats",
		"admin.network",
		"admin.policy",
		"admin.settings",
		"self.manage",
	},
}

# Which workload (mTLS certificate CN) may ask for which action.
trusted_callers := {
	"account.read": {"account"},
	"transaction.transfer": {"transaction"},
	"transaction.history": {"account", "transaction"},
	"admin.dashboard": {"gateway"},
	"admin.audit": {"gateway"},
	"admin.session_policy": {"gateway"},
	"admin.devices": {"gateway"},
	"admin.quarantine": {"gateway"},
	"admin.search": {"gateway", "account"},
	"admin.user_control": {"gateway"},
	"admin.fraud": {"gateway"},
	"admin.containers": {"gateway"},
	"admin.threats": {"gateway"},
	"admin.network": {"gateway"},
	"admin.policy": {"gateway"},
	"admin.settings": {"gateway"},
	"self.manage": {"gateway"},
	"ops.accounts": {"account"},
	"ops.transactions": {"account"},
	"ops.freeze": {"account"},
	"ops.limits": {"account"},
	"ops.approve": {"transaction"},
	"transaction.cancel": {"transaction"},
	"beneficiary.manage": {"account"},
}

# ------------------------------------------------ tunable policy (module 8)
# Administrators tune these through the gateway's safe editor, which writes
# data.zt_policy. The editor is RESTRICT-ONLY and this file enforces that again:
# data can lower a limit but never raise it above the baseline below, can make
# medium risk deny instead of step-up, and can add deny rules - never allow rules.
baseline := {
	"transfer_limit_customer": 200000,
	"high_value_threshold": 50000,
	"medium_risk_action": "step_up",
	"custom_denies": [],
}

default policy_data := {}

policy_data := p if {
	p := data.zt_policy
	is_object(p)
}

cfg := object.union(baseline, policy_data)

cfg_valid if {
	is_number(cfg.transfer_limit_customer)
	is_number(cfg.high_value_threshold)
	cfg.medium_risk_action in {"step_up", "deny"}
	is_array(cfg.custom_denies)
}

# Per-transfer ceiling by role (INR).
transfer_limit := {"customer": min([baseline.transfer_limit_customer, cfg.transfer_limit_customer])}

# Transfers at or above this amount wait for an operations officer (maker-checker).
high_value_threshold := min([baseline.high_value_threshold, cfg.high_value_threshold])

# Custom rules can never block the policy editor itself, the audit trail or a user's own security settings.
protected_actions := {"admin.policy", "admin.audit", "self.manage"}

# ------------------------------------------------------------------- helpers
role := input.subject.role

is_owner if {
	input.resource.owner
	input.resource.owner == input.subject.user
}

granted if input.action in permissions[role]

granted if {
	is_owner
	concat(":", [input.action, "own"]) in permissions[role]
}

granted if concat(":", [input.action, "any"]) in permissions[role]

is_transfer if input.action == "transaction.transfer"

# ------------------------------------------------------------- deny reasons
deny contains "mfa_required" if not input.subject.mfa == true

deny contains "role_not_permitted" if not granted

deny contains "untrusted_workload" if {
	not input.context.caller in trusted_callers[input.action]
}

deny contains "risk_too_high" if {
	is_transfer
	input.context.risk_level == "high"
}

deny contains "risk_unknown" if {
	is_transfer
	not input.context.risk_level in {"low", "medium", "high"}
}

# F21: money only moves from a device the customer has verified
deny contains "device_not_trusted" if {
	is_transfer
	not input.context.device_trust == "trusted" # missing value must deny, not be undefined
}

deny contains "amount_over_limit" if {
	is_transfer
	input.context.amount > transfer_limit[role]
}

# Frozen accounts can neither send nor receive (a missing status must deny).
deny contains "account_frozen" if {
	is_transfer
	not input.context.sender_status == "active"
}

deny contains "payee_account_frozen" if {
	is_transfer
	not input.context.receiver_status == "active"
}

within_daily_limit if input.context.daily_used + input.context.amount <= input.context.daily_limit

deny contains "daily_limit_exceeded" if {
	is_transfer
	not within_daily_limit
}

# A corrupt policy document must stop money, not open the gates.
deny contains "policy_config_invalid" if {
	is_transfer
	not cfg_valid
}

deny contains "medium_risk_denied_by_policy" if {
	is_transfer
	input.context.risk_level == "medium"
	cfg.medium_risk_action == "deny"
}

deny contains reason if {
	some rule in cfg.custom_denies
	rule.action == input.action
	rule.role in {role, "*"}
	not input.action in protected_actions
	reason := concat(":", ["custom_rule", rule.id])
}

# ---------------------------------------------------------- maker-checker
needs_approval if {
	is_transfer
	input.context.amount >= high_value_threshold
}

# ------------------------------------------------------------------ step-up
needs_step_up if {
	is_transfer
	input.context.risk_level == "medium"
	not input.context.step_up == true
}

# ----------------------------------------------------------------- decision
allow if {
	count(deny) == 0
	not needs_step_up
}

step_up if {
	count(deny) == 0
	needs_step_up
}

reasons := deny | {"step_up_required"} if needs_step_up

else := deny

decision := {
	"allow": allow,
	"step_up": step_up,
	"needs_approval": needs_approval,
	"reasons": reasons,
}

# Policy simulation: the same decision evaluated against a candidate policy
# document (input.policy) without changing what is live.
simulate := d if {
	d := decision with data.zt_policy as object.get(input, "policy", {})
}

default allow := false

default needs_approval := false

default step_up := false
