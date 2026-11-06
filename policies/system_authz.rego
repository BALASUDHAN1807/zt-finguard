# Protects OPA's own API. OPA runs with --authentication=tls, so the caller's
# identity is the subject of its client certificate. Only the services that
# make authorization decisions may query policy. Rego code can never be changed
# at runtime; the only writable document is data.zt_policy (the restrict-only
# tunables of the module-8 policy editor), and only the gateway may write it.
package system.authz

default allow := false

decision_makers := {"account", "transaction", "gateway"}

caller_cn := cn if {
	some part in split(input.identity, ",")
	startswith(trim_space(part), "CN=")
	cn := substring(trim_space(part), 3, -1)
}

allow if {
	input.method == "POST"
	input.path == ["v1", "data", "finguard", "authz", "decision"]
	caller_cn in decision_makers
}

# health probe (any authenticated workload)
allow if {
	input.method == "GET"
	input.path == ["health"]
	caller_cn
}

# module 8: the gateway publishes the active tunables and runs simulations
allow if {
	input.method in {"PUT", "GET"}
	input.path == ["v1", "data", "zt_policy"]
	caller_cn == "gateway"
}

allow if {
	input.method == "POST"
	input.path == ["v1", "data", "finguard", "authz", "simulate"]
	caller_cn == "gateway"
}
