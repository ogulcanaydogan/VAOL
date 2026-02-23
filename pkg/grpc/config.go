// Package grpc provides the gRPC API server for the VAOL ledger.
package grpc

// Config holds the gRPC server configuration.
type Config struct {
	// Addr is the gRPC listen address (e.g. ":9090").
	// If empty, the gRPC server is disabled.
	Addr string

	// Version is the server version string returned by Health RPCs.
	Version string
}
