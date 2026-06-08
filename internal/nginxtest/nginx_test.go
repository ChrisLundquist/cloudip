// Package nginxtest is an integration test that proves a Cloud-Attribution MMDB
// works unmodified behind nginx's stock ngx_http_geoip2_module, fed a client IP
// over the PROXY protocol. It builds a tiny database in-process, writes an nginx
// config, validates it parses (nginx -t), launches nginx in the foreground, and
// curls it with a spoofed cloud client IP in the PROXY header.
//
// It skips cleanly when the moving parts aren't present:
//   - nginx not on PATH
//   - the geoip2 module is neither built in nor locatable as a .so
//     (set CLOUDIP_GEOIP2_MODULE to point at ngx_http_geoip2_module.so)
//   - curl missing or too old for --haproxy-clientip
package nginxtest

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func TestNginxGeoIP2ProxyProtocol(t *testing.T) {
	nginxBin, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("nginx not on PATH")
	}
	curlBin, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not on PATH")
	}
	if !curlSupportsHAProxyClientIP(t, curlBin) {
		t.Skip("curl lacks --haproxy-clientip (need curl >= 8.2.0)")
	}
	loadModule := locateGeoIP2Module(t, nginxBin)

	dir := t.TempDir()
	mmdbPath := filepath.Join(dir, "cloud.mmdb")
	writeTestMMDB(t, mmdbPath)

	port := freePort(t)
	confPath := filepath.Join(dir, "nginx.conf")
	accessLog := filepath.Join(dir, "access.log")
	writeNginxConf(t, confPath, nginxConfParams{
		LoadModule: loadModule,
		Dir:        dir,
		MMDB:       mmdbPath,
		Port:       port,
		AccessLog:  accessLog,
	})

	// Step 1: config must parse.
	if out, err := runNginx(dir, confPath, nginxBin, "-t"); err != nil {
		t.Fatalf("nginx -t failed: %v\n%s", err, out)
	}

	// Step 2: launch nginx in the foreground (daemon off; in the config). nginx
	// forks a worker that inherits stdout, so we run it in its own process group
	// and tear the whole group down on cleanup — otherwise cmd.Wait() would block
	// on the worker holding the stdout pipe open.
	cmd := exec.Command(nginxBin, "-p", dir+string(os.PathSeparator), "-c", confPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 3 * time.Second
	var nginxOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &nginxOut, &nginxOut
	if err := cmd.Start(); err != nil {
		t.Fatalf("start nginx: %v", err)
	}
	defer func() {
		// SIGQUIT the process group (master + workers) for a graceful stop.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGQUIT)
		_ = cmd.Wait()
		t.Logf("nginx output:\n%s", nginxOut.String())
	}()

	if !waitForPort(port, 5*time.Second) {
		t.Fatalf("nginx did not start listening on %d\n%s", port, nginxOut.String())
	}

	// Step 3: a spoofed AWS client IP in the PROXY header should attribute to AWS.
	got := curlWhoami(t, curlBin, port, "52.94.0.1")
	if want := "aws us-east-1 AMAZON"; strings.TrimSpace(got) != want {
		t.Errorf("AWS lookup via PROXY protocol = %q, want %q", strings.TrimSpace(got), want)
	}

	// A non-cloud IP attributes to nothing (empty provider fields).
	gotMiss := curlWhoami(t, curlBin, port, "203.0.113.7")
	if f := strings.Fields(gotMiss); len(f) != 0 {
		t.Errorf("non-cloud IP attribution = %q, want empty", strings.TrimSpace(gotMiss))
	}

	// Step 4: the attribution made it into the access log line, too.
	logs, err := os.ReadFile(accessLog)
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if !bytes.Contains(logs, []byte("52.94.0.1 cloud=aws/us-east-1")) {
		t.Errorf("access log missing attributed line:\n%s", logs)
	}
}

// writeTestMMDB builds a tiny Cloud-Attribution database with one AWS network.
func writeTestMMDB(t *testing.T, path string) {
	t.Helper()
	pre, err := netip.ParsePrefix("52.94.0.0/22")
	if err != nil {
		t.Fatal(err)
	}
	entries := func(yield func(attribution.Entry, error) bool) {
		yield(attribution.Entry{
			Network: pre,
			Record: attribution.Record{
				Provider: "aws", Region: "us-east-1", Services: []string{"AMAZON"},
			},
		}, nil)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := attribution.Build(entries, f, attribution.BuildOptions{}); err != nil {
		t.Fatal(err)
	}
}

type nginxConfParams struct {
	LoadModule string
	Dir        string
	MMDB       string
	Port       int
	AccessLog  string
}

func writeNginxConf(t *testing.T, path string, p nginxConfParams) {
	t.Helper()
	load := ""
	if p.LoadModule != "" {
		load = "load_module " + p.LoadModule + ";\n"
	}
	conf := load + fmt.Sprintf(`
daemon off;
worker_processes 1;
pid %[1]s/nginx.pid;
error_log %[1]s/error.log warn;
events { worker_connections 64; }
http {
    client_body_temp_path %[1]s/body;
    proxy_temp_path       %[1]s/proxy;
    fastcgi_temp_path     %[1]s/fastcgi;
    uwsgi_temp_path       %[1]s/uwsgi;
    scgi_temp_path        %[1]s/scgi;

    geoip2 %[2]s {
        $cloud_provider source=$proxy_protocol_addr provider;
        $cloud_region   source=$proxy_protocol_addr region;
        $cloud_service  source=$proxy_protocol_addr services 0;
    }

    log_format cloud '$proxy_protocol_addr cloud=$cloud_provider/$cloud_region svc=$cloud_service';
    access_log %[3]s cloud;

    server {
        listen %[4]d proxy_protocol;
        location = /whoami {
            default_type text/plain;
            return 200 '$cloud_provider $cloud_region $cloud_service\n';
        }
    }
}
`, strings.TrimRight(p.Dir, string(os.PathSeparator)), p.MMDB, p.AccessLog, p.Port)
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runNginx(dir, conf, bin string, extra ...string) (string, error) {
	args := append([]string{"-p", dir + string(os.PathSeparator), "-c", conf}, extra...)
	out, err := exec.Command(bin, args...).CombinedOutput()
	return string(out), err
}

// locateGeoIP2Module returns the load_module path, or "" if the module is built
// statically into nginx. It skips the test if the module can't be found at all.
func locateGeoIP2Module(t *testing.T, nginxBin string) string {
	t.Helper()
	v, _ := exec.Command(nginxBin, "-V").CombinedOutput()
	if bytes.Contains(v, []byte("geoip2")) {
		return "" // statically compiled in
	}
	if env := os.Getenv("CLOUDIP_GEOIP2_MODULE"); env != "" {
		if fileExists(env) {
			return env
		}
		t.Skipf("CLOUDIP_GEOIP2_MODULE=%s not found", env)
	}
	for _, c := range []string{
		"/opt/homebrew/lib/nginx/modules/ngx_http_geoip2_module.so",
		"/usr/local/lib/nginx/modules/ngx_http_geoip2_module.so",
		"/usr/lib/nginx/modules/ngx_http_geoip2_module.so",
		"/usr/share/nginx/modules/ngx_http_geoip2_module.so",
		"/etc/nginx/modules/ngx_http_geoip2_module.so",
	} {
		if fileExists(c) {
			return c
		}
	}
	t.Skip("ngx_http_geoip2_module not built in and no .so found (set CLOUDIP_GEOIP2_MODULE)")
	return ""
}

func curlSupportsHAProxyClientIP(t *testing.T, curlBin string) bool {
	t.Helper()
	out, _ := exec.Command(curlBin, "--help", "all").CombinedOutput()
	return bytes.Contains(out, []byte("--haproxy-clientip"))
}

func curlWhoami(t *testing.T, curlBin string, port int, clientIP string) string {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/whoami", port)
	out, err := exec.Command(curlBin, "-s", "--haproxy-protocol", "--haproxy-clientip", clientIP, url).CombinedOutput()
	if err != nil {
		t.Fatalf("curl %s: %v\n%s", clientIP, err, out)
	}
	return string(out)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
