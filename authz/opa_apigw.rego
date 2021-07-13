package apigw

import data.authzs

default allow = false

runtime := opa.runtime()

allow {
	# valid_jwt
	reqested_resource_allowed
}

reqested_resource_allowed {
	authz = authzs[_]
	regex.match(authz.resource, input.resource)
	operation_allowed(authz.operations, input.operation)
	allowed_to_match(authz.allowed_to.user_groups, token.payload["cognito:groups"])
	allowed_to_match(authz.allowed_to.web_app_client_ids, token.payload.client_id)
}

reqested_resource_allowed {
	authz = authzs[_]
	regex.match(authz.resource, input.resource)
	operation_allowed(authz.operations, input.operation)
	allowed_to_match(authz.allowed_to.system_client_ids, token.payload.client_id)
}

operation_allowed(allowed, value) {
	allowed[_] = "*"
}

operation_allowed(allowed, value) {
	allowed[_] = value
}

allowed_to_match(allowed, values) {
	allowed[_] = values[_]
}

allowed_to_match(allowed, values) {
	allowed[_] = "*"
}

allowed_to_match(allowed, value) {
	allowed[_] = value
}

# https://play.openpolicyagent.org/p/9af2cRleIv
valid_jwt {
	jwks = jwks_request(runtime.env.JWKS_URL).body
	io.jwt.verify_rs256(input.token, json.marshal(jwks))
}

jwks_request(url) = http.send({
	"url": url,
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 3600, # Cache response for an hour
})

token = {"payload": payload} {
	[header, payload, signature] := io.jwt.decode(input.token)
}
