package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/ChrisLundquist/cloudip/proto/cloudattrpb"
	"github.com/ChrisLundquist/cloudip/server"
)

// serveConfig is the listen configuration for serve.
type serveConfig struct {
	httpAddr string // "" disables HTTP
	grpcAddr string // "" disables gRPC
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	in := fs.String("in", "cloud.mmdb", "MMDB path to serve")
	httpAddr := fs.String("http", ":8080", "HTTP listen address (empty to disable)")
	grpcAddr := fs.String("grpc", ":9090", "gRPC listen address (empty to disable)")
	index := fs.Bool("index", false, "build an in-memory provider index at load for faster /v1/provider lookups (trades heap for speed)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	svc, err := server.NewServiceIndexed(*in, *index)
	if err != nil {
		return err
	}
	defer svc.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP -> reload the (atomically replaced) file in place. The goroutine is
	// joined before svc.Close() (deferred above) runs, so no reload overlaps close.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if err := svc.Reload(); err != nil {
					fmt.Fprintf(os.Stderr, "reload failed: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "reloaded %s (build_epoch=%d)\n", *in, svc.DB().BuildTime().Unix())
				}
			}
		}
	}()

	err = serve(ctx, svc, serveConfig{httpAddr: *httpAddr, grpcAddr: *grpcAddr})
	stop()    // ensure ctx is cancelled so the SIGHUP goroutine exits...
	wg.Wait() // ...then join it before the deferred svc.Close() runs
	return err
}

// serve starts the configured HTTP and gRPC servers and blocks until ctx is
// cancelled (clean shutdown) or a server fails. It is decoupled from signal
// handling so it can be driven by a context in tests.
func serve(ctx context.Context, svc *server.Service, cfg serveConfig) error {
	errc := make(chan error, 2)

	// Acquire BOTH listeners before starting any serve goroutine: if gRPC fails to
	// listen we just close the HTTP listener and return, with no Serve goroutine
	// ever started — which avoids racing httpSrv.Shutdown against httpSrv.Serve's
	// listener registration (Shutdown only closes listeners Serve has registered).
	var httpLn, grpcLn net.Listener
	if cfg.httpAddr != "" {
		ln, err := net.Listen("tcp", cfg.httpAddr)
		if err != nil {
			return fmt.Errorf("http listen: %w", err)
		}
		httpLn = ln
	}
	if cfg.grpcAddr != "" {
		ln, err := net.Listen("tcp", cfg.grpcAddr)
		if err != nil {
			if httpLn != nil {
				httpLn.Close() // don't leave the HTTP listener open on early return
			}
			return fmt.Errorf("grpc listen: %w", err)
		}
		grpcLn = ln
	}

	var httpSrv *http.Server
	if httpLn != nil {
		httpSrv = &http.Server{
			Handler:           server.NewHTTPHandler(svc),
			ReadHeaderTimeout: 5 * time.Second, // bound slow-header (Slowloris) clients
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			fmt.Fprintf(os.Stderr, "HTTP listening on %s\n", httpLn.Addr())
			if err := httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("http: %w", err)
			}
		}()
	}

	var grpcSrv *grpc.Server
	if grpcLn != nil {
		grpcSrv = grpc.NewServer()
		cloudattrpb.RegisterCloudAttributionServer(grpcSrv, server.NewGRPCServer(svc))
		go func() {
			fmt.Fprintf(os.Stderr, "gRPC listening on %s\n", grpcLn.Addr())
			if err := grpcSrv.Serve(grpcLn); err != nil {
				errc <- fmt.Errorf("grpc: %w", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "shutting down")
		shutdown(httpSrv, grpcSrv)
		return nil
	case err := <-errc:
		shutdown(httpSrv, grpcSrv)
		return err
	}
}

func shutdown(httpSrv *http.Server, grpcSrv *grpc.Server) {
	if httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}
	if grpcSrv != nil {
		grpcSrv.GracefulStop()
	}
}
