module github.com/trappsec-dev/trappsec/packages/go/echov5

go 1.26.0

require (
	github.com/labstack/echo/v5 v5.2.0
	github.com/trappsec-dev/trappsec/packages/go v0.2.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace github.com/trappsec-dev/trappsec/packages/go => ../
