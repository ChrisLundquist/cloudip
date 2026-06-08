package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ChrisLundquist/cloudip/server"
)

// TestServeStartStop drives the decoupled serve() with a context: it starts the
// HTTP+gRPC servers on ephemeral ports, confirms HTTP serves, then cancels and
// asserts a clean shutdown (no hang, no error).
func TestServeStartStop(t *testing.T) {
	svc, err := server.NewService(writeTinyDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, svc, serveConfig{httpAddr: httpAddr, grpcAddr: grpcAddr}) }()

	if !waitDial(httpAddr, 5*time.Second) {
		cancel()
		t.Fatal("HTTP server never came up")
	}

	// A real request goes through.
	resp, err := http.Get("http://" + httpAddr + "/healthz")
	if err != nil {
		cancel()
		t.Fatalf("GET /healthz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("/healthz status %d body %s", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned error on clean shutdown: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("serve did not shut down within 8s")
	}
}

// TestServeGRPCListenFailureShutsDownHTTP covers the early-return path: if the
// gRPC port can't bind, the already-started HTTP server must be shut down too.
func TestServeGRPCListenFailureShutsDownHTTP(t *testing.T) {
	svc, err := server.NewService(writeTinyDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	httpAddr := freeAddr(t)

	// Occupy a port and hand it to gRPC so its Listen fails.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	grpcAddr := occupied.Addr().String()

	err = serve(context.Background(), svc, serveConfig{httpAddr: httpAddr, grpcAddr: grpcAddr})
	if err == nil {
		t.Fatal("expected gRPC listen error")
	}
	// HTTP must no longer be listening (it was shut down on the early return).
	if waitDial(httpAddr, 500*time.Millisecond) {
		t.Error("HTTP server left running after gRPC listen failure")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return fmt.Sprintf("127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port)
}

func waitDial(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}
