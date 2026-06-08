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
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/ChrisLundquist/cloudip/proto/cloudattrpb"
	"github.com/ChrisLundquist/cloudip/server"
)

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

	// SIGHUP -> reload the (atomically replaced) file in place.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
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

	errc := make(chan error, 2)

	var httpSrv *http.Server
	if *httpAddr != "" {
		httpSrv = &http.Server{
			Addr:              *httpAddr,
			Handler:           server.NewHTTPHandler(svc),
			ReadHeaderTimeout: 5 * time.Second, // bound slow-header (Slowloris) clients
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			fmt.Fprintf(os.Stderr, "HTTP listening on %s\n", *httpAddr)
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("http: %w", err)
			}
		}()
	}

	var grpcSrv *grpc.Server
	if *grpcAddr != "" {
		lis, err := net.Listen("tcp", *grpcAddr)
		if err != nil {
			shutdown(httpSrv, nil) // don't leave the HTTP server running on early return
			return fmt.Errorf("grpc listen: %w", err)
		}
		grpcSrv = grpc.NewServer()
		cloudattrpb.RegisterCloudAttributionServer(grpcSrv, server.NewGRPCServer(svc))
		go func() {
			fmt.Fprintf(os.Stderr, "gRPC listening on %s\n", *grpcAddr)
			if err := grpcSrv.Serve(lis); err != nil {
				errc <- fmt.Errorf("grpc: %w", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "shutting down")
	case err := <-errc:
		stop()
		shutdown(httpSrv, grpcSrv)
		return err
	}
	shutdown(httpSrv, grpcSrv)
	return nil
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
