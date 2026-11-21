// Package telemetry exports request traces over OTLP, with t10-modkit's
// telemetry. What's this service's own is here: its name.
package telemetry

import (
	"context"
	"net/http"

	shared "github.com/xiant10/t10-modkit/telemetry"
)

const serviceName = "auth-server"

// Setup starts the exporter and returns a shutdown that flushes it.
func Setup(ctx context.Context, endpoint string) (func(context.Context) error, error) {
	return shared.Setup(ctx, serviceName, endpoint)
}

// Wrap traces one route, named by its pattern, and marks its chat session.
func Wrap(pattern string, next http.Handler) http.Handler {
	return shared.Wrap(pattern, next)
}

// Inject puts the trace on ctx into an outgoing request's headers as a W3C
// traceparent, so the service it calls joins this request's trace.
func Inject(ctx context.Context, h http.Header) {
	shared.Inject(ctx, h)
}
