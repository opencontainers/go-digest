module github.com/opencontainers/go-digest/blake3

go 1.18

require (
	github.com/opencontainers/go-digest v0.0.0
	github.com/zeebo/blake3 v0.1.1
)

replace github.com/opencontainers/go-digest => ../

require golang.org/x/sys v0.0.0-20201014080544-cc95f250f6bc // indirect
