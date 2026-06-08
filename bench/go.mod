// Separate module so the head-to-head dependency on rezmoss/go-cloudip (and its
// cidranger transitive dep) stays out of the main module. Run with:
//   cd bench && go test -bench . -benchmem
module github.com/ChrisLundquist/cloudip/bench

go 1.26.4

require (
	github.com/ChrisLundquist/cloudip v0.0.0
	github.com/rezmoss/go-cloudip v0.0.4
)

require (
	github.com/maxmind/mmdbwriter v1.2.0 // indirect
	github.com/oschwald/maxminddb-golang/v2 v2.4.0 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/yl2chen/cidranger v1.0.2 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace github.com/ChrisLundquist/cloudip => ../
