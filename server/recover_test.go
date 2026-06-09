package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRecoverHTTPTurnsPanicInto500(t *testing.T) {
	h := recoverHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/lookup/1.2.3.4", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestRecoverHTTPPassesThroughNormalResponses(t *testing.T) {
	h := recoverHTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418 (no panic must pass through untouched)", rec.Code)
	}
}

func TestRecoveryUnaryInterceptor(t *testing.T) {
	_, err := RecoveryUnaryInterceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/test/Method"},
		func(context.Context, any) (any, error) { panic("boom") })
	if status.Code(err) != codes.Internal {
		t.Fatalf("err code = %v, want Internal", status.Code(err))
	}
}

func TestRecoveryUnaryInterceptorPassesThrough(t *testing.T) {
	resp, err := RecoveryUnaryInterceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/test/Method"},
		func(context.Context, any) (any, error) { return "ok", nil })
	if err != nil || resp != "ok" {
		t.Fatalf("resp=%v err=%v, want ok/nil", resp, err)
	}
}

func TestRecoveryStreamInterceptor(t *testing.T) {
	err := RecoveryStreamInterceptor(nil, nil,
		&grpc.StreamServerInfo{FullMethod: "/test/Stream"},
		func(any, grpc.ServerStream) error { panic("boom") })
	if status.Code(err) != codes.Internal {
		t.Fatalf("err code = %v, want Internal", status.Code(err))
	}
}
