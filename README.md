# gyzor

[![CI](https://github.com/eilandert/gyzor/actions/workflows/ci.yml/badge.svg)](https://github.com/eilandert/gyzor/actions/workflows/ci.yml)
[![Release](https://github.com/eilandert/gyzor/actions/workflows/release.yml/badge.svg)](https://github.com/eilandert/gyzor/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/eilandert/gyzor.svg)](https://pkg.go.dev/github.com/eilandert/gyzor)

> A fast, dependency-light **Go [pyzor](https://github.com/SpamExperts/pyzor)
> client** — `check` / `report` / `revoke` — for streaming pipelines, with zero
> on-disk message handling.

gyzor speaks the pyzor wire protocol — UDP, the SHA1 message digest, anonymous
or account-signed requests — **byte-for-byte compatibly with the reference
client**, so the public `public.pyzor.org` servers accept its requests. The
digest is the part that has to be exact (a wrong digest fingerprints a different
message); it is verified against real pyzor 1.1.2 in CI.

Use it two ways:

- **As a Go library** — `import "github.com/eilandert/gyzor/pyzor"` and call
  `Client.Check/Report/Whitelist` in-process. This is how the
  [gozer](https://github.com/eilandert/gozer) backend uses it: linked directly,
  no subprocess, no socket.
- **As a CLI** — `gyzor check|report|revoke` (message on stdin, never touches
  disk), plus a `gyzor serve` HTTP sidecar.

## Quick start

```go
// library
import "github.com/eilandert/gyzor/pyzor"

c := pyzor.New(pyzor.Config{Home: "/var/lib/pyzor"}) // drop-in with ~/.pyzor
res := c.Check(msg)                                   // res.Count, res.Whitelist
spam := res.Hit(0, 0)                                 // reference-pyzor verdict
_ = c.Report(msg)
_ = c.Whitelist(msg)
```

```sh
# CLI — exit 0 = listed (spam), 1 = not listed
gyzor check < message.eml
```

## The DRP family

Three pure-Go network clients, one orchestrator binary, one Docker deployment —
each wire-compatible with the original perl/python/C tool:

| Repo | Role |
|------|------|
| [gdcc](https://github.com/eilandert/gdcc) | DCC client — library + CLI |
| [gazor](https://github.com/eilandert/gazor) | Razor 2 client — library + CLI |
| [gyzor](https://github.com/eilandert/gyzor) | Pyzor client — library + CLI |
| [gozer](https://github.com/eilandert/gozer) | backend binary — links all three in-process behind one HTTP endpoint |
| [rspamd-dcc-razor-pyzor](https://github.com/eilandert/rspamd-dcc-razor-pyzor) | Docker deployment — gozer image + rspamd plugin + dovecot sieve |

The three clients share the same `Client` shape, CLI/env conventions and `serve`
API. Background: [why we rewrote them in Go](https://github.com/eilandert/rspamd-dcc-razor-pyzor#the-go-rewrite-gazor-gyzor-gdcc-gozer).

**Why Go?** The classic pyzor client is Python and forks per message — an
interpreter start on every check inside a mail pipeline. gyzor is one static
binary: no fork, the message stays in RAM, and the digest is parity-tested
against real pyzor.

## CLI

```sh
gyzor check   < message.eml    # exit 0 = listed (spam), 1 = not listed
gyzor report  < message.eml    # report as spam
gyzor revoke  < message.eml    # whitelist (revoke a prior report)
gyzor digest  < message.eml    # print the SHA1 digest (debug)
gyzor ping                     # server reachability
gyzor genkey                   # print a fresh "salt,key" (hand the key to the pyzord admin)
gyzor register --user NAME     # save credentials to the homedir accounts file
gyzor serve                    # HTTP sidecar: /check /report /revoke /metrics /healthz
```

Every option is settable by flag **or** environment variable (flag > env >
homedir file > default):

| flag | env | meaning |
|------|-----|---------|
| `--homedir` | `GYZOR_HOMEDIR` | pyzor home with `servers`/`accounts` files (default `~/.pyzor`, also honours `PYZOR_HOME`) |
| `--servers` | `GYZOR_SERVERS` | comma list of `host:port`; bypasses the homedir `servers` file and pyzor discovery |
| `--timeout` | `GYZOR_TIMEOUT` | per-server network budget |
| `--r-count` / `--wl-count` | `GYZOR_R_COUNT` / `GYZOR_WL_COUNT` | report / whitelist thresholds for the check verdict |
| `--verbose` | `GYZOR_VERBOSE` | per-server logging (errors are logged either way) |
| `--user` / `--key` / `--salt` | `GYZOR_USER` / `GYZOR_KEY` / `GYZOR_SALT` | account identity used to sign every request. Needs **both** `--user` and `--key`; `--key` may be the combined `salt,key` field. An explicit identity overrides the homedir `accounts` file for all servers. (`--salt` is cosmetic — stored, never sent.) |
| `--listen` / `--unix` / `--token` | `GYZOR_LISTEN` / `GYZOR_UNIX` / `GYZOR_TOKEN` | `serve` HTTP listen address `host:port` (default loopback `127.0.0.1:8078`), optional Unix socket, shared secret (**required to bind a non-loopback address**) |
| `--max-concurrent` | `GYZOR_MAX_CONCURRENT` | `serve` max in-flight requests (default 8; over the limit → `503`) |
| `--log-stdout` | `GYZOR_LOG_STDOUT` | `serve` send info/access logs to stdout; **errors/warnings stay on stderr**. `/report`+`/revoke` access logged always, `/check` under `--verbose`. |

With `--servers`/`GYZOR_SERVERS` unset, gyzor falls back to the homedir
`servers` file and finally the public default; account credentials come from the
homedir `accounts` file (drop-in with an existing `~/.pyzor` or `/var/lib/pyzor`).
An explicit but invalid `--servers` value is an error, not a silent fallback to a
different destination.

### Credentials

Most public servers accept the implicit `anonymous` account, so no setup is
needed. For an authenticated account, supply the identity three ways (precedence
order):

1. **Flags / env** — `--user`+`--key` (`GYZOR_USER`/`GYZOR_KEY`). Good for a
   one-off or a container env; applies to every server and overrides the file.
2. **`gyzor register`** — saves the identity to `$homedir/accounts` (dir `0700`,
   file `0600`) for every configured server, so later runs sign automatically.
   Idempotent: re-registering a server replaces its entry.
3. **The `accounts` file** itself (`host : port : username : salt,key`), drop-in
   with reference pyzor.

```sh
# 1. generate a key (random by default; set GYZOR_PASSPHRASE to derive one):
gyzor genkey
# salt,key:
# 3f2a…,9c81…              # give the username + key to the pyzord admin

# 2. or do both at once — generate AND persist for the configured servers.
#    register saves to the accounts file AND prints the identity as env lines:
gyzor --servers public.pyzor.org:24441 --user alice register
# register: saved account "alice" for 1 server(s) to /home/you/.pyzor/accounts
# register: environment variables for this identity (use instead of the file):
# GYZOR_USER=alice
# GYZOR_SALT=edb6…
# GYZOR_KEY=e0f5…
# register: give this username and key to the pyzord administrator: …

# 3. persist a key the admin already issued you:
gyzor --user alice --key <salt>,<key> register

# the env lines are bare KEY=value, so they pipe straight into an env file:
gyzor --servers public.pyzor.org:24441 --user alice register | grep '^GYZOR_' > gyzor.env
```

`genkey` mirrors reference `pyzor genkey` (`key = SHA1(SHA1(salt)+passphrase)`,
random salt) and only prints — the salt stays client-side; only the username and
key go to the server administrator. `gyzor register` is the "save it for me"
version.

### serve mode

`gyzor serve` runs a plain **HTTP/1.1** server. **Safe by default:** it binds
loopback (`127.0.0.1:8078`) and bounds in-flight requests (`--max-concurrent`,
default 8 → `503` over the limit). Exposing it on another address requires a
`--token` — it refuses a non-loopback bind without one. Set `--listen host:port`
/ `GYZOR_LISTEN` (and/or a Unix socket via `--unix`):

- `POST /check` → `{"action":"reject|accept|unknown","hit":bool,"count":N,"whitelist":N,"servers":[...]}`
  (`reject` = listed spam, `accept` = clean; **`unknown` + HTTP 502** when a
  queried server failed — incomplete evidence is not reported as clean; the
  per-server breakdown is included for debugging)
- `POST /report` → `{"reported":true}`
- `POST /revoke` → `{"revoked":true}`
- `GET /metrics` → Prometheus exposition (request/verdict counters, latency histogram)
- `GET /healthz`

POST the raw RFC-822 message as the body (`--data-binary` keeps the bytes intact —
the digest is computed over them):

```sh
gyzor serve --listen :8078 --token s3cret &

# query — JSON verdict (drop the header if no --token was set)
curl -s --data-binary @message.eml \
  -H 'X-GYZOR-Token: s3cret' http://127.0.0.1:8078/check
# {"action":"accept","hit":false,"count":0,"whitelist":0,"servers":[…]}

# report as spam / revoke (whitelist) — Bearer works too
curl -s --data-binary @spam.eml -H 'Authorization: Bearer s3cret' http://127.0.0.1:8078/report
curl -s --data-binary @ham.eml  -H 'Authorization: Bearer s3cret' http://127.0.0.1:8078/revoke
curl -s http://127.0.0.1:8078/metrics      # no auth
```

An optional `--token`/`GYZOR_TOKEN` requires a `Bearer` or `X-GYZOR-Token` header
on `/check`, `/report` and `/revoke`. Default bind is loopback `127.0.0.1:8078`
(gozer is `8077`, `gazor serve` `8079`, `gdcc serve` `8080`). Messages over
16 MiB are rejected (`413`), not silently truncated.

## Correctness

The digest is the make-or-break: a wrong digest means the server sees a different
signature and the check/report is useless. The `pyzor` package is a faithful port
of pyzor's `digest.py`, gated by a **parity test** that compares gyzor's digest to
real pyzor 1.1.2 over a 15-message corpus — plain, HTML, multipart/alternative,
base64 attachment, quoted-printable, CRLF, non-ASCII (UTF-8, latin-1, NBSP,
high-byte), an embedded `message/rfc822`, malformed base64, and a missing MIME
boundary. Account signing is pinned to golden vectors from pyzor's `account.py`.

The multi-server check verdict matches reference pyzor exactly: a hit requires
every server to answer, at least one report count above the threshold, and no
whitelist count above it — counts are never summed across servers. Responses are
validated (required fields, matching thread id, numeric counts) before they are
trusted.

## Build / test

```sh
go build ./cmd/gyzor
go test ./...                       # incl. the pyzor 1.1.2 digest parity gate + serve tests
go test -fuzz=FuzzCompute ./pyzor   # MIME/normalizer fuzzing
```

## See also

- The rest of the family is in the table above.
- [The Go rewrite: gazor, gyzor, gdcc, gozer](https://github.com/eilandert/rspamd-dcc-razor-pyzor#the-go-rewrite-gazor-gyzor-gdcc-gozer) — why the perl/python/C clients were rewritten in Go
- Blog article: <https://deb.myguard.nl/2026/06/rspamd-dcc-razor-pyzor-docker-backend/>
- Docker Hub: <https://hub.docker.com/r/eilandert/rspamd-dcc-razor-pyzor>

## License

**GPLv3** — see [LICENSE](LICENSE). gyzor is a Go port of the pyzor client
(itself GPL); as a derivative work it is released under the GPL. The digest and
signing algorithms are verified for byte-for-byte parity against the reference
pyzor client in CI.
