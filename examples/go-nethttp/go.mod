module trappsec-go-nethttp-example

go 1.24.0

require github.com/trappsec-dev/trappsec/packages/go/nethttp v0.0.0

require github.com/trappsec-dev/trappsec/packages/go v0.0.0 // indirect

replace (
	github.com/trappsec-dev/trappsec/packages/go => ../../packages/go
	github.com/trappsec-dev/trappsec/packages/go/nethttp => ../../packages/go/nethttp
)
