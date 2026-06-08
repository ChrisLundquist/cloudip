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
	if err := fs.Parse(args); err != nil {
		return err
	}

	svc, err := server.NewService(*in)
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

	var httpSrv *http.Server
	if cfg.httpAddr != "" {
		ln, err := net.Listen("tcp", cfg.httpAddr)
		if err != nil {
			return fmt.Errorf("http listen: %w", err)
		}
		httpSrv = &http.Server{
			Handler:           server.NewHTTPHandler(svc),
			ReadHeaderTimeout: 5 * time.Second, // bound slow-header (Slowloris) clients
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			fmt.Fprintf(os.Stderr, "HTTP listening on %s\n", ln.Addr())
			if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("http: %w", err)
			}
		}()
	}

	var grpcSrv *grpc.Server
	if cfg.grpcAddr != "" {
		lis, err := net.Listen("tcp", cfg.grpcAddr)
		if err != nil {
			shutdown(httpSrv, nil) // don't leave the HTTP server running
			return fmt.Errorf("grpc listen: %w", err)
		}
		grpcSrv = grpc.NewServer()
		cloudattrpb.RegisterCloudAttributionServer(grpcSrv, server.NewGRPCServer(svc))
		go func() {
			fmt.Fprintf(os.Stderr, "gRPC listening on %s\n", lis.Addr())
			if err := grpcSrv.Serve(lis); err != nil {
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
