package server

import (
	"context"
	"io"
	"testing"

	pb "github.com/ChrisLundquist/cloudip/proto/cloudattrpb"
)

func TestGRPCLookupAndVersion(t *testing.T) {
	svc, err := NewService(buildTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	g := NewGRPCServer(svc)

	res, err := g.Lookup(context.Background(), &pb.LookupRequest{Ip: "52.94.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.Record.Provider != "aws" || len(res.Record.Services) != 2 {
		t.Errorf("lookup result = %+v", res)
	}
	if res.Record.Network != "52.94.0.0/22" {
		t.Errorf("network = %q, want 52.94.0.0/22", res.Record.Network)
	}

	miss, err := g.Lookup(context.Background(), &pb.LookupRequest{Ip: "203.0.113.1"})
	if err != nil {
		t.Fatal(err)
	}
	if miss.Found {
		t.Error("expected miss for 203.0.113.1")
	}

	// Reputation host: categories must populate over gRPC.
	repu, err := g.Lookup(context.Background(), &pb.LookupRequest{Ip: "171.25.193.25"})
	if err != nil {
		t.Fatal(err)
	}
	if repu.Record.GetProvider() != "tor" || len(repu.Record.GetCategories()) != 2 {
		t.Errorf("reputation record = %+v", repu.Record)
	}

	// invalid ip -> error
	if _, err := g.Lookup(context.Background(), &pb.LookupRequest{Ip: "nope"}); err == nil {
		t.Error("expected error for invalid ip")
	}

	ver, err := g.Version(context.Background(), &pb.VersionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if ver.DatabaseType != "Cloud-Attribution" || ver.BuildEpoch != 1718000000 {
		t.Errorf("version = %+v", ver)
	}
}

// fakeBatchStream feeds a fixed set of requests and captures responses,
// standing in for the generated bidi stream in BatchLookup.
type fakeBatchStream struct {
	pb.CloudAttribution_BatchLookupServer
	reqs []*pb.LookupRequest
	i    int
	sent []*pb.LookupResult
}

func (f *fakeBatchStream) Recv() (*pb.LookupRequest, error) {
	if f.i >= len(f.reqs) {
		return nil, io.EOF
	}
	r := f.reqs[f.i]
	f.i++
	return r, nil
}

func (f *fakeBatchStream) Send(r *pb.LookupResult) error {
	f.sent = append(f.sent, r)
	return nil
}

func (f *fakeBatchStream) Context() context.Context { return context.Background() }

func TestGRPCBatchLookup(t *testing.T) {
	svc, err := NewService(buildTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	g := NewGRPCServer(svc)

	stream := &fakeBatchStream{reqs: []*pb.LookupRequest{
		{Ip: "52.94.0.1"},   // hit
		{Ip: "203.0.113.1"}, // miss
		{Ip: "not-an-ip"},   // error
	}}
	if err := g.BatchLookup(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.sent) != 3 {
		t.Fatalf("sent %d results, want 3", len(stream.sent))
	}
	if !stream.sent[0].Found || stream.sent[0].Error != "" {
		t.Errorf("hit result = %+v", stream.sent[0])
	}
	if stream.sent[1].Found || stream.sent[1].Error != "" {
		t.Errorf("miss result should be found=false, no error: %+v", stream.sent[1])
	}
	// The malformed IP must surface an error, not masquerade as a plain miss.
	if stream.sent[2].Found || stream.sent[2].Error == "" {
		t.Errorf("error result should carry Error and found=false: %+v", stream.sent[2])
	}
}
