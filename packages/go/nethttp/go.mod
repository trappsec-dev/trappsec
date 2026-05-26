module github.com/trappsec-dev/trappsec/packages/go/nethttp

go 1.25.0

require github.com/trappsec-dev/trappsec/packages/go v0.2.0

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
)

replace github.com/trappsec-dev/trappsec/packages/go => ../
