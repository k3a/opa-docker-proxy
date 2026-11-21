# opa-docker-proxy

A policy-enforcing proxy for the Docker Engine API. It listens on its own Unix socket (or TCP address), evaluates every request against [OPA](https://www.openpolicyagent.org/) Rego policies, and only forwards allowed requests to the real Docker socket. Optionally it can also **isolate** clients from each other's resources via injected labels.

```
docker client ──► opa-docker-proxy ──(allowed)──► /var/run/docker.sock
                    │  Rego policies decide
                    └─(denied)──► 403 + reason
```

Module: `github.com/k3a/opa-docker-proxy` (Go, OPA v1 embedded as a library — no separate OPA server).

## Quick start

```sh
go build -o opa-docker-proxy .
cp config.yaml.example /etc/opa-docker-proxy/config.yaml   # edit, see "Configuration"
mkdir -p /etc/opa-docker-proxy && cp -r policies /etc/opa-docker-proxy/
./opa-docker-proxy -c /etc/opa-docker-proxy/config.yaml

DOCKER_HOST=unix:///var/run/opa-docker-proxy.sock docker ps
```

### CLI flags

| Flag | Meaning |
|------|---------|
| `-c <path>` | Config file. Without it, `/etc/opa-docker-proxy/config.yaml` is used if present, otherwise built-in defaults. An explicit path must exist. |
| `-i` | Enable isolation; name defaults to first 16 hex chars of SHA-256 of the CWD |
| `--isolation-name <name>` | Explicit isolation name (implies `-i`) |

## Configuration

YAML file; defaults are applied first, then overridden by the file. See `config.yaml.example`.

| Key | Default | Notes |
|-----|---------|-------|
| `listen.socket` | `/var/run/opa-docker-proxy.sock` | Unix socket; chmod `0666`; stale file is removed on start. Takes precedence over `address`. |
| `listen.address` | – | TCP `host:port`, used only if `socket` is empty. |
| `docker_socket` | `/var/run/docker.sock` (or `$DOCKER_SOCKET`) | Upstream Docker daemon. |
| `policies_path` | `/etc/opa-docker-proxy/policies` | Directory of `.rego` files (non-recursive). |
| `logging.level` | `info` | `debug`/`info`/`warn`/`error` |
| `logging.format` | `text` | `text` (compact request line) or `json` |
| `logging.log_allowed` | `true` | Log allowed requests |
| `logging.log_denied` | `true` | Log denied requests |
| `logging.log_opa` | `true` | Route Rego `print()` output to the log |

Validation: at least one of `listen.socket`/`listen.address`, non-empty `docker_socket` and `policies_path`, valid level/format. There is no authentication of its own — access control is the socket permissions plus your policies.

## Request flow (`proxy/proxy.go`)

1. Read the body; determine client IP (`X-Forwarded-For` → `X-Real-Ip` → remote addr; Unix socket clients show up as `@`).
2. Build OPA input (below). If `Content-Type` is `application/json` the body is validated and parsed (400 on invalid JSON); otherwise `body` stays a raw string.
3. Evaluate `data.policies.allow` and `data.policies.reason`. Deny → HTTP 403 with the reason; evaluation error → 500. No result = deny.
4. If isolation is on: transform the request and check resource ownership (403 otherwise).
5. Forward via `httputil.ReverseProxy` to the Docker socket (HTTP upgrades for attach/exec are handled natively).

### OPA input

```json
{
  "method": "POST",
  "api_ver": "v1.44",
  "path": "/containers/create",
  "body": { "...parsed JSON..." },
  "headers": { "Content-Type": "application/json" },
  "client_ip": "127.0.0.1"
}
```

The version prefix is stripped from `path`, so policies match clean paths like `/containers/create`.

## Policies (`policies/`)

All files are `package policies` and are loaded together, in one module set. Contract: the engine reads `data.policies.allow` (bool) and `data.policies.reason` (string).

**Model:** deny-set. Rules add messages to the `denial` set; `allow` is true when `denial` is empty. Files are numbered by purpose:

| File | Effect |
|------|--------|
| `01_framework.rego` | `allow` / `reason` definitions (defaults to deny). Don't remove. |
| `02_container_security.rego` | On `/containers/create` deny: privileged, `CapAdd` of `SYS_ADMIN`/`NET_ADMIN`/`SYS_PTRACE`/`ALL`, host network/PID/userns, any bind mounts (`Binds` or `Mounts` of type bind). |
| `03_block_exec_build.rego` | Deny container exec, `/exec/*/start`, and `/build`. |
| `04_readonly_resources.rego` | Only `GET` on `/volumes`, `/networks`, `/images`. |
| `05_block_secrets_configs.rego` | Deny `/secrets*` and `/configs*`. |
| `06_internal_network.rego` | Deny clients outside RFC1918/loopback (Unix-socket clients exempt). |
| `50_allow_safe_host_mounts.rego` | Extra `allow` rule: permits `/containers/create` with bind mounts when every source starts with `/dev/` or `/temp/agent/`, contains no `..` component, and no other denial exists. |
| `50_allow_safe_host_mounts_test.rego` | `opa test` unit tests for the above. |

Notes:
- `policies_extra/deny_admin.rego` is **not loaded** by default; it is an optional stricter rule set (denies container lifecycle ops, container creation, all DELETEs). Copy it into the policies directory to enable it.
- Every `*.rego` file in `policies_path` is loaded, including `*_test.rego`.
- The safe-mount override matches the exact denial text `"bind mounts are not allowed"`. The `Mounts`-array variant in `02` interpolates the mount into its message, so it is not matched by that override. If you rely on `Mounts`-based safe mounts, verify with the tests.
- Policies are compiled once at startup — restart to apply changes.
- Test policies: `opa test policies/ -v` (requires the OPA CLI).

## Isolation (`isolation/`, `-i` / `--isolation-name`)

Self-contained optional feature so several users/projects can share one Docker daemon without seeing each other's resources. When enabled, label `io.opa-docker-proxy.isolation=<name>` is:

- **injected** into bodies of create requests and build `labels`;
- **filtered** into list queries (`filters`) and prune calls;
- **checked** on per-resource requests (containers, images, volumes, networks; execs resolve to their parent container) by inspecting the resource via the daemon — a mismatch returns 403.

To remove the feature: delete `isolation/`, the flag handling in `main.go`, and the few calls in `proxy.go`.

## Layout

```
main.go          CLI, wiring, signal handling
config/          YAML config + defaults + validation
opa/             Loads/compiles .rego, evaluates allow+reason, print() hook
proxy/           HTTP server, reverse proxy, OPA input, request logging
isolation/       Optional label-based resource isolation
logger/          slog setup + compact request log format
utils/           API version-prefix splitting
policies/        Default Rego policy set (+ tests)
policies_extra/  Optional extra policies (not loaded by default)
```
