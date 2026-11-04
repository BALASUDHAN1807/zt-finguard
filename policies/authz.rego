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
#                "device_trust": "trusted|pending"}
# }
#
# result = {"allow": bool, "step_up": bool, "reasons": [..]}
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
	"self.manage": {"gateway"},
}

# Per-transfer ceiling by role (INR).
transfer_limit := {"customer": 200000}

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
	"reasons": reasons,
}

default allow := false

default step_up := false
