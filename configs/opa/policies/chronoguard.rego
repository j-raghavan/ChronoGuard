package chronoguard.authz

default allow := false

allow if {
	agent_authenticated
	domain_allowed
	time_window_valid
	rate_limit_ok
}

agent_authenticated if {
	input.attributes.source.principal
	get_agent_policy(input.attributes.source.principal)
}

# Extract hostname from host:port (e.g., "example.com:443" -> "example.com")
extract_hostname(host) := hostname if {
	contains(host, ":")
	parts := split(host, ":")
	hostname := parts[0]
}

extract_hostname(host) := host if {
	not contains(host, ":")
}

domain_allowed if {
	policy := get_agent_policy(input.attributes.source.principal)
	requested_host := input.attributes.request.http.host
	requested_domain := extract_hostname(requested_host)
	requested_domain in policy.allowed_domains
	not requested_domain in policy.blocked_domains
}

time_window_valid if {
	policy := get_agent_policy(input.attributes.source.principal)
	not policy.time_restrictions
}

time_window_valid if {
	policy := get_agent_policy(input.attributes.source.principal)
	restrictions := policy.time_restrictions

	restrictions.enabled

	weekday_index := {
		"Monday": 0,
		"Tuesday": 1,
		"Wednesday": 2,
		"Thursday": 3,
		"Friday": 4,
		"Saturday": 5,
		"Sunday": 6,
	}

	local_weekday := weekday_index[time.weekday(time.now_ns())]
	local_weekday in restrictions.allowed_days

	utc_clock := time.clock(time.now_ns())
	utc_minutes := (utc_clock[0] * 60) + utc_clock[1]

	# Use count to force type inference - this works around OPA's type checker
	offset_value := restrictions.timezone_offset_minutes
	adjusted_minutes := utc_minutes + offset_value
	wrapped_minutes := adjusted_minutes % 1440
	normalized_minutes := wrapped_minutes + 1440
	local_minutes := normalized_minutes % 1440

	some range in restrictions.time_ranges
	within_time_range(range, local_minutes)
}

within_time_range(range, minute) if {
	start_time := (range.start_hour * 60) + range.start_minute
	end_time := (range.end_hour * 60) + range.end_minute
	start_time <= end_time
	minute >= start_time
	minute <= end_time
}

within_time_range(range, minute) if {
	start_time := (range.start_hour * 60) + range.start_minute
	end_time := (range.end_hour * 60) + range.end_minute
	start_time > end_time
	minute >= start_time
}

within_time_range(range, minute) if {
	start_time := (range.start_hour * 60) + range.start_minute
	end_time := (range.end_hour * 60) + range.end_minute
	start_time > end_time
	minute <= end_time
}

rate_limit_ok if {
	policy := get_agent_policy(input.attributes.source.principal)
	not policy.rate_limits
}

rate_limit_ok if {
	policy := get_agent_policy(input.attributes.source.principal)
	policy.rate_limits
	context := object.get(input, "rate_limit_context", {})

	minute_count := object.get(context, "minute_count", 0)
	hour_count := object.get(context, "hour_count", 0)
	day_count := object.get(context, "day_count", 0)
	burst_count := object.get(context, "burst_count", 0)

	minute_count < policy.rate_limits.requests_per_minute
	hour_count < policy.rate_limits.requests_per_hour
	day_count < policy.rate_limits.requests_per_day
	burst_count < policy.rate_limits.burst_limit
}

# Extract CN from full DN (e.g., "CN=demo-agent-001,O=ChronoGuard,..." -> "demo-agent-001")
extract_cn(dn) := cn if {
	# Split by comma and find CN=
	parts := split(dn, ",")
	some part in parts
	startswith(part, "CN=")
	cn := substring(part, 3, -1)
}

# Fallback: if no CN found, return the original string
extract_cn(dn) := dn if {
	not contains(dn, "CN=")
}

get_agent_policy(agent_id) := policy if {
	cn := extract_cn(agent_id)
	policy := data.policies[cn]
}

get_agent_policy(agent_id) := {} if {
	cn := extract_cn(agent_id)
	not data.policies[cn]
}

decision_metadata := {
	"agent_id": input.attributes.source.principal,
	"domain": input.attributes.request.http.host,
	"method": input.attributes.request.http.method,
	"path": input.attributes.request.http.path,
	"timestamp": time.now_ns(),
	"decision": allow,
}

