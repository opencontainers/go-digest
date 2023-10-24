module github.com/opencontainers/go-digest/blake3

go 1.18

require (
	github.com/opencontainers/go-digest v1.0.0
	github.com/zeebo/blake3 v0.2.3
)

replace github.com/opencontainers/go-digest => ../

require (
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	golang.org/x/sys v0.13.0 // indirect
)
