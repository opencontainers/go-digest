module github.com/opencontainers/go-digest/blake3

go 1.15

require (
	github.com/opencontainers/go-digest v0.0.0
	github.com/zeebo/blake3 v0.1.1
)

replace (
 github.com/opencontainers/go-digest => ../
)
