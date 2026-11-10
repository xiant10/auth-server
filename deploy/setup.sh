#!/bin/sh
# One-shot setup, safe to repeat: creates the first platform admin, and the
# service account of each deployed service whose secret is set. A deployment
# sets only the secrets of what it runs. A runtime in clients.yaml with no
# account stops auth-server from starting, so a missing secret still shows. An
# existing admin or service is left as it is, so changing a secret here rotates
# nothing.
set -eu

authctl bootstrap --if-empty \
	--username="$AUTH_SETUP_ADMIN" \
	--tenant-id="$AUTH_SETUP_TENANT_ID" \
	--tenant-name="$AUTH_SETUP_TENANT_NAME"

# service <name> <secret>: adds the account when the secret is set.
service() {
	if [ -n "$2" ]; then
		AUTHCTL_SERVICE_SECRET="$2" authctl service-add --if-missing --name="$1"
	fi
}
service t10-livekit-agent "${LIVEKIT_AGENT_SECRET:-}"
service agent-pi "${AGENT_PI_SECRET:-}"
service agent-sales "${AGENT_SALES_SECRET:-}"
service agent-ti "${AGENT_TI_SECRET:-}"
service agent-ti-property "${AGENT_TI_PROPERTY_SECRET:-}"
service t10-collab "${T10_COLLAB_SECRET:-}"
service t10-knowledge "${T10_KNOWLEDGE_SECRET:-}"
service t10-property "${T10_PROPERTY_SECRET:-}"
service ai-gateway "${AI_GATEWAY_SECRET:-}"
service ai-gateway-tools "${AI_GATEWAY_TOOLS_SECRET:-}"
service t10-automations "${T10_AUTOMATIONS_SECRET:-}"
