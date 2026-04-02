module trappsec-go-nethttp-example

go 1.24.0

require (
	github.com/trappsec-dev/trappsec/packages/go/nethttp v0.0.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.63.0
	go.opentelemetry.io/otel v1.38.0
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.38.0
	go.opentelemetry.io/otel/sdk v1.38.0
)

require (
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/trappsec-dev/trappsec/packages/go v0.0.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace (
	github.com/trappsec-dev/trappsec/packages/go => ../../packages/go
	github.com/trappsec-dev/trappsec/packages/go/nethttp => ../../packages/go/nethttp
)
