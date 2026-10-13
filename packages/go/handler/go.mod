module github.com/trappsec-dev/trappsec/packages/go/handler

go 1.26.0

require github.com/trappsec-dev/trappsec/packages/go v0.2.0

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
)

replace github.com/trappsec-dev/trappsec/packages/go => ../
