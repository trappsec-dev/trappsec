module trappsec-go-echo-example

go 1.26.0

require (
	github.com/labstack/echo-otel/v5 v5.0.0
	github.com/labstack/echo/v5 v5.2.1
	github.com/trappsec-dev/trappsec/packages/go/echo v0.0.0
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.38.0
	go.opentelemetry.io/otel/sdk v1.47.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/trappsec-dev/trappsec/packages/go v0.2.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace (
	github.com/trappsec-dev/trappsec/packages/go => ../../packages/go
	github.com/trappsec-dev/trappsec/packages/go/echo => ../../packages/go/echo
)
