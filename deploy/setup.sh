#!/bin/sh
# One-shot setup, safe to repeat: creates the first platform admin, the
# service account of every runtime in clients.yaml, and any deployed service or
# business module whose secret is set. An existing admin or service is left as
# it is, so changing a secret here rotates nothing.
set -eu

authctl bootstrap --if-empty \
	--username="$AUTH_SETUP_ADMIN" \
	--tenant-id="$AUTH_SETUP_TENANT_ID" \
	--tenant-name="$AUTH_SETUP_TENANT_NAME"
AUTHCTL_SERVICE_SECRET="$LIVEKIT_AGENT_SECRET" authctl service-add --if-missing --name=t10-livekit-agent
AUTHCTL_SERVICE_SECRET="$AGENT_PI_SECRET" authctl service-add --if-missing --name=agent-pi
AUTHCTL_SERVICE_SECRET="$AGENT_SALES_SECRET" authctl service-add --if-missing --name=agent-sales
if [ -n "${T10_COLLAB_SECRET:-}" ]; then
	AUTHCTL_SERVICE_SECRET="$T10_COLLAB_SECRET" authctl service-add --if-missing --name=t10-collab
fi
if [ -n "${AI_GATEWAY_SECRET:-}" ]; then
	AUTHCTL_SERVICE_SECRET="$AI_GATEWAY_SECRET" authctl service-add --if-missing --name=ai-gateway
fi
