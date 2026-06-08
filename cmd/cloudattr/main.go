// Command cloudattr builds, serves, and queries the Cloud-Attribution MMDB.
//
//	cloudattr build  --source rezmoss --out cloud.mmdb
//	cloudattr lookup 52.94.0.1
//	cloudattr export --in cloud.mmdb --out cloud.csv
//	cloudattr verify --in cloud.mmdb
//	cloudattr serve  --in cloud.mmdb --http :8080 --grpc :9090
package main

import (
	"fmt"
	"os"

	_ "github.com/ChrisLundquist/cloudip/plugins/all" // register provider plugins
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "build":
		err = runBuild(args)
	case "lookup":
		err = runLookup(args)
	case "export":
		err = runExport(args)
	case "verify":
		err = runVerify(args)
	case "serve":
		err = runServe(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "cloudattr: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cloudattr %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cloudattr — cloud IP attribution

Usage:
  cloudattr build  [--source rezmoss|rezmoss-all|direct] [--fixtures DIR] [--providers a,b] [--out FILE] [--csv FILE] [--max-drop FRAC]
  cloudattr lookup IP [IP ...]      [--in FILE] [--format text|json]
  cloudattr lookup -f FILE          [--in FILE] [--format text|json]
  cloudattr export [--in FILE] [--out FILE]
  cloudattr verify [--in FILE]
  cloudattr serve  [--in FILE] [--http ADDR] [--grpc ADDR]

Run "cloudattr <command> -h" for command flags.
`)
}
