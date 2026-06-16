// Command gyzor is a Go reimplementation of the pyzor client (check / report /
// revoke). The core lives in package pyzor, imported in-process by the rspamd
// shim; this command is the standalone CLI front-end.
//
// CLI usage (message on stdin, never touches disk):
//
//	gyzor check   < message.eml   # exit 0 = listed (spam), 1 = not listed
//	gyzor report  < message.eml   # report as spam
//	gyzor revoke  < message.eml   # whitelist (revoke a report)
//	gyzor digest  < message.eml   # print the SHA1 digest (debug)
//	gyzor ping                    # check server reachability
//	gyzor genkey                  # print a fresh "salt,key" (give key to admin)
//	gyzor register --user NAME    # save credentials to the homedir accounts file
//	gyzor serve                   # HTTP sidecar: /check /report /revoke /metrics /healthz
//
// Every option is settable by flag OR environment variable (flag > env >
// homedir identity file > default): --homedir/GYZOR_HOMEDIR,
// --servers/GYZOR_SERVERS, --timeout/GYZOR_TIMEOUT, --r-count/GYZOR_R_COUNT,
// --wl-count/GYZOR_WL_COUNT, --verbose/GYZOR_VERBOSE, the serve-mode
// --listen/GYZOR_LISTEN, --unix/GYZOR_UNIX, --token/GYZOR_TOKEN, and the
// account identity --user/GYZOR_USER, --key/GYZOR_KEY, --salt/GYZOR_SALT
// (--key may be the combined "salt,key" field; an explicit identity applies to
// every server, overriding the homedir accounts file). genkey reads an optional
// passphrase from GYZOR_PASSPHRASE (empty -> random key).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/eilandert/gyzor/pyzor"
)

var version = "dev"

const repoURL = "https://github.com/eilandert/gyzor"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gyzor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	homedir := fs.String("homedir", envStr("GYZOR_HOMEDIR", defaultHome()), "pyzor home dir (servers/accounts files)")
	serversArg := fs.String("servers", os.Getenv("GYZOR_SERVERS"), "comma-separated host:port list (overrides homedir/servers)")
	timeout := fs.Duration("timeout", envDur("GYZOR_TIMEOUT", 5*time.Second), "per-server network timeout")
	rCount := fs.Int("r-count", envInt("GYZOR_R_COUNT"), "check: report count strictly above this counts as a hit")
	wlCount := fs.Int("wl-count", envInt("GYZOR_WL_COUNT"), "check: whitelist count strictly above this clears a hit")
	verbose := fs.Bool("verbose", envBool("GYZOR_VERBOSE"), "log per-server detail (errors are logged regardless)")
	user := fs.String("user", os.Getenv("GYZOR_USER"), "account username (with --key, signs every request; overrides the accounts file)")
	key := fs.String("key", os.Getenv("GYZOR_KEY"), "account key hex (or the combined \"salt,key\" field); requires --user")
	salt := fs.String("salt", os.Getenv("GYZOR_SALT"), "account salt hex (cosmetic; stored in the accounts file, not used to sign)")
	listen := fs.String("listen", envStr("GYZOR_LISTEN", "127.0.0.1:8078"), "serve: HTTP listen address host:port — serves /check,/report,/revoke,/metrics,/healthz (default loopback 127.0.0.1:8078; '' disables TCP)")
	unixSock := fs.String("unix", os.Getenv("GYZOR_UNIX"), "serve: also serve the HTTP API on this Unix socket path (optional)")
	token := fs.String("token", os.Getenv("GYZOR_TOKEN"), "serve: shared-secret token; required to bind a non-loopback address")
	maxConc := fs.Int("max-concurrent", envIntOr("GYZOR_MAX_CONCURRENT", runtime.NumCPU()), "serve: max in-flight requests, default = CPU count (over the limit -> 503)")
	logStdout := fs.Bool("log-stdout", envBool("GYZOR_LOG_STDOUT"), "serve: send info/access logs to stdout; errors stay on stderr")
	showVer := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVer {
		fmt.Fprintln(stdout, "gyzor", version)
		return 0
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "usage: gyzor [flags] check|report|revoke|digest|ping|genkey|register|serve")
		return 2
	}
	op := rest[0]
	// Allow flags after the subcommand too (gyzor serve --listen ...), not just
	// before it — Go's flag package otherwise stops at the first positional.
	if err := fs.Parse(rest[1:]); err != nil {
		return 2
	}

	// A --key given as the combined "salt,key" accounts-file field is split so
	// either form works on the command line.
	if *salt == "" && strings.Contains(*key, ",") {
		s, k, _ := strings.Cut(*key, ",")
		*salt, *key = s, k
	}

	// genkey never contacts a server and needs no client/identity.
	if op == "genkey" {
		return runGenkey(stdout, stderr)
	}

	acc, err := buildAccount(op, *user, *key, *salt)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	cli, err := buildClient(*homedir, *serversArg, *timeout, *verbose, acc, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	switch op {
	case "register":
		return runRegister(*homedir, cli.Servers, *user, *key, *salt, stdout, stderr)
	case "serve":
		return runServe(cli, serveConfig{listen: *listen, unix: *unixSock, token: *token, maxConc: *maxConc, rCount: *rCount, wlCount: *wlCount, logStdout: *logStdout, verbose: *verbose}, stderr)
	case "ping":
		if cli.Ping() {
			fmt.Fprintln(stdout, "ok")
			return 0
		}
		fmt.Fprintln(stderr, "ping failed")
		return 1
	case "digest":
		raw, err := readCapped(stdin, maxBody)
		if err != nil {
			fmt.Fprintln(stderr, "read stdin:", err)
			return 2
		}
		fmt.Fprintln(stdout, pyzor.Compute(raw))
		return 0
	case "check", "report", "revoke":
		raw, err := readCapped(stdin, maxBody)
		if err != nil {
			fmt.Fprintln(stderr, "read stdin:", err)
			return 2
		}
		return doMessageOp(cli, op, raw, *rCount, *wlCount, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown op %q\n", op)
		return 2
	}
}

func doMessageOp(cli *pyzor.Client, op string, raw []byte, rCount, wlCount int, stdout, stderr io.Writer) int {
	switch op {
	case "check":
		res := cli.Check(raw)
		for _, s := range res.Servers {
			// Mirror pyzor's per-server output: "host:port\t(code, 'diag')\tcount\twl".
			if s.Err != nil {
				fmt.Fprintf(stdout, "%s\t(%d, '%s')\n", s.Server, 0, s.Err)
				continue
			}
			fmt.Fprintf(stdout, "%s\t(%d, '%s')\t%d\t%d\n", s.Server, s.Code, s.Diag, s.Count, s.WLCount)
		}
		// pyzor decides a hit per-server (never sums counts across servers).
		if res.Hit(rCount, wlCount) {
			return 0 // hit
		}
		return 1
	case "report":
		if cli.Report(raw) {
			return 0
		}
		fmt.Fprintln(stderr, "report failed")
		return 1
	case "revoke":
		if cli.Whitelist(raw) {
			return 0
		}
		fmt.Fprintln(stderr, "revoke failed")
		return 1
	}
	return 2
}

// buildAccount turns the identity flags into the account that signs requests.
// An explicit identity needs BOTH a username and a key; supplying only one is a
// usage error rather than a silent fallback to anonymous (which would send
// requests unsigned to a server that expects authentication). register is
// exempt — it derives/persists credentials itself and signs nothing — so it
// always gets the zero (anonymous) account here.
func buildAccount(op, user, key, salt string) (pyzor.Account, error) {
	if op == "register" {
		return pyzor.Account{}, nil
	}
	switch {
	case user == "" && key == "":
		return pyzor.Account{}, nil // no identity -> anonymous / homedir accounts file
	case user == "":
		return pyzor.Account{}, fmt.Errorf("--key/GYZOR_KEY requires --user/GYZOR_USER")
	case key == "":
		return pyzor.Account{}, fmt.Errorf("--user/GYZOR_USER requires --key/GYZOR_KEY (or run: gyzor register)")
	}
	return pyzor.Account{Username: user, Salt: salt, Key: key}, nil
}

func buildClient(homedir, serversArg string, timeout time.Duration, verbose bool, acc pyzor.Account, logw io.Writer) (*pyzor.Client, error) {
	cfg := pyzor.Config{Home: homedir, Timeout: timeout, Verbose: verbose, DefaultAccount: acc}
	if logw != nil {
		cfg.Log = func(s string) { fmt.Fprintln(logw, s) }
	}
	if serversArg != "" {
		servers, err := parseServersArg(serversArg)
		if err != nil {
			return nil, err
		}
		cfg.Servers = servers
	}
	return pyzor.New(cfg), nil
}

// parseServersArg parses the --servers override. An explicit but invalid value
// is a usage error rather than a silent fallback to the homedir/default server:
// contacting a different destination than the one the operator named could leak
// the message or report to an unintended server.
func parseServersArg(arg string) ([]pyzor.Server, error) {
	var out []pyzor.Server
	for _, part := range splitComma(arg) {
		host, port, ok := splitHostPort(part)
		if !ok {
			return nil, fmt.Errorf("invalid --servers entry %q (want host:port)", part)
		}
		out = append(out, pyzor.Server{Host: host, Port: port})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--servers is empty")
	}
	return out, nil
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitHostPort(s string) (host string, port int, ok bool) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, false
	}
	return h, n, true
}

func defaultHome() string {
	if h := os.Getenv("PYZOR_HOME"); h != "" {
		return h
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".pyzor")
	}
	return ".pyzor"
}

// --- env-var fallbacks (flag > env > default) ---

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envBool(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// envIntOr reads an int env var, returning def when unset/invalid.
func envIntOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// errTooLarge is returned by readCapped when input exceeds the cap, so the
// caller can reject it (413 / usage error) instead of processing a truncated
// prefix.
var errTooLarge = errors.New("message exceeds the maximum size")

// readCapped reads up to max bytes and returns errTooLarge if there is more (it
// reads max+1 so an exactly-max message is accepted, an over-cap one rejected).
func readCapped(r io.Reader, max int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, errTooLarge
	}
	return b, nil
}
