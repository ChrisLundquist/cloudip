package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A panic in one lookup handler must not cascade into an outage. The middlewares
// here convert a panic into a clean error response — HTTP 500 / gRPC Internal —
// and log the stack to stderr so the failure is diagnosable without taking the
// process (gRPC) or connection (HTTP) down. They are hand-rolled rather than
// pulling in grpc-ecosystem/go-grpc-middleware, keeping the dependency set small
// (same rationale as the hand-written /metrics text format).

// recoverHTTP wraps next so a panic is logged and answered with a 500 rather than
// abruptly dropping the connection. net/http already recovers per-connection, but
// it sends no response body; this returns a well-formed JSON error and keeps the
// server serving. http.ErrAbortHandler is net/http's intentional-abort sentinel
// and is re-raised so the standard library can handle it as designed.
func recoverHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			fmt.Fprintf(os.Stderr, "panic serving %s %s: %v\n%s", r.Method, r.URL.Path, v, debug.Stack())
			// If the handler already committed a status, WriteHeader is a no-op; this
			// is best-effort. Our handlers write exactly once at the end, so in
			// practice a panic happens before any write.
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}()
		next.ServeHTTP(w, r)
	})
}

// RecoveryUnaryInterceptor recovers a panic in a unary gRPC handler, logging the
// stack and returning codes.Internal instead of crashing the server process.
func RecoveryUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if v := recover(); v != nil {
			fmt.Fprintf(os.Stderr, "panic in %s: %v\n%s", info.FullMethod, v, debug.Stack())
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	return handler(ctx, req)
}

// RecoveryStreamInterceptor is RecoveryUnaryInterceptor for streaming handlers
// (e.g. BatchLookup).
func RecoveryStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if v := recover(); v != nil {
			fmt.Fprintf(os.Stderr, "panic in %s: %v\n%s", info.FullMethod, v, debug.Stack())
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	return handler(srv, ss)
}
