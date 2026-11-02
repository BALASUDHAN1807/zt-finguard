# Protects OPA's own API. OPA runs with --authentication=tls, so the caller's
# identity is the subject of its client certificate. Only the services that
# make authorization decisions may query policy; nobody may change policy or
# data at runtime through the API.
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
