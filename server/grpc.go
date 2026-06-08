package server

import (
	"context"
	"errors"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ChrisLundquist/cloudip/attribution"
	pb "github.com/ChrisLundquist/cloudip/proto/cloudattrpb"
)

// GRPCServer adapts a Service to the generated CloudAttribution gRPC service.
type GRPCServer struct {
	pb.UnimplementedCloudAttributionServer
	svc *Service
}

// NewGRPCServer wraps a Service for gRPC serving.
func NewGRPCServer(svc *Service) *GRPCServer { return &GRPCServer{svc: svc} }

// Lookup resolves a single IP.
func (g *GRPCServer) Lookup(_ context.Context, req *pb.LookupRequest) (*pb.LookupResult, error) {
	rec, found, err := g.svc.Lookup(req.GetIp())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.LookupResult{Ip: req.GetIp(), Found: found, Record: recordToProto(rec)}, nil
}

// BatchLookup resolves a bidirectional stream of IPs, one result per request.
func (g *GRPCServer) BatchLookup(stream pb.CloudAttribution_BatchLookupServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		rec, found, lerr := g.svc.Lookup(req.GetIp())
		res := &pb.LookupResult{Ip: req.GetIp(), Found: found}
		if lerr != nil {
			res.Error = lerr.Error() // surface per-IP errors instead of a silent miss
		} else {
			res.Record = recordToProto(rec)
		}
		if err := stream.Send(res); err != nil {
			return err
		}
	}
}

// Version reports the loaded database's build epoch and metadata.
func (g *GRPCServer) Version(context.Context, *pb.VersionRequest) (*pb.VersionResponse, error) {
	md := g.svc.DB().Metadata()
	return &pb.VersionResponse{
		BuildEpoch:   g.svc.DB().BuildTime().Unix(),
		DatabaseType: md.DatabaseType,
		NodeCount:    uint64(md.NodeCount),
	}, nil
}

// recordToProto converts the reader Record into its protobuf form.
func recordToProto(r attribution.Record) *pb.Record {
	var synced int64
	if !r.SyncedAt.IsZero() {
		synced = r.SyncedAt.Unix()
	}
	return &pb.Record{
		Provider:   r.Provider,
		Region:     r.Region,
		Services:   r.Services,
		Categories: r.Categories,
		Ipv6:       r.IPv6,
		Source:     r.Source,
		SyncedAt:   synced,
		Ext:        r.Ext,
	}
}
