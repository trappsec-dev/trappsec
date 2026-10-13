// Tests of the handler adapter against real routers. A separate module so the
// adapter itself carries no router dependency.
module github.com/trappsec-dev/trappsec/packages/go/handler/routertest

go 1.26.0

replace (
	github.com/trappsec-dev/trappsec/packages/go => ../../
	github.com/trappsec-dev/trappsec/packages/go/handler => ../
)

require (
	github.com/go-chi/chi/v5 v5.4.0
	github.com/gorilla/mux v1.8.1
	github.com/trappsec-dev/trappsec/packages/go/handler v0.0.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/trappsec-dev/trappsec/packages/go v0.2.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
)
