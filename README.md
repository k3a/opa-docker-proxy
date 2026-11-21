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
| `-i` | Enable isolation (also settable in the config); name defaults to first 16 hex chars of SHA-256 of the CWD |
| `--isolation-name <name>` | Explicit isolation name (implies `-i`, overrides `isolation.name`) |
| `-s <path>` | Listen socket (overrides `listen.socket`) |
| `--print-name` | Print the isolation name (CWD hash unless named) and exit |
| `--print-socket` | Print the socket path `-i` would use and exit |
| `clean [--all-isolated]` | Subcommand: remove all containers, networks, volumes and images labelled with the isolation name (`--isolation-name`, else config, else CWD hash). `--all-isolated` removes every labelled object regardless of name. Talks to `docker_socket` directly, not through the proxy. |

With `-i` / `--isolation-name` (and no `-s`), the proxy always listens on `$XDG_RUNTIME_DIR/opa-docker-proxy/<name>.sock` (fallback `~/.local/share/opa-docker-proxy/`; a per-user `0700` directory, socket mode `0600`, other users cannot connect) (name = isolation name, or the CWD hash; non-filename-safe names are hashed). (`listen.socket` is ignored; isolation enabled only via config uses it when `listen.socket` is the default). With `-i` logs always go to `<name>.log` in that directory (mode `0600`) instead of stdout; startup errors are also printed to stderr. Both files are removed on exit (SIGINT/SIGTERM exits 0); a SIGKILL leaves them behind. Script usage:

```sh
SOCK=$(opa-docker-proxy --print-socket)   # same path the daemon will use
opa-docker-proxy -i & PID=$!
until [ -S "$SOCK" ]; do sleep 0.1; done
DOCKER_HOST=unix://$SOCK docker run --rm alpine true
kill $PID; wait $PID
```

## Configuration

YAML file; defaults are applied first, then overridden by the file. `config.yaml.example` documents every option with the strict defaults; **`config.dev.yaml.example`** is a ready-made development profile (run/stop/exec/delete containers, manage networks and volumes, pull images — only on resources created through the proxy).

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
| `isolation.enabled` | `false` | Label-based resource isolation, see "Isolation". The `-i` flag enables it too. |
| `isolation.name` | CWD hash | Label value. Keep stable across restarts. |
| `isolation.mode` | `full` | `full` (private-daemon view) or `writes` |
| `policy` | read-only, hardened | Policy options passed to Rego as `data.config`, see "Policy config" |

Validation: at least one of `listen.socket`/`listen.address`, non-empty `docker_socket` and `policies_path`, valid level/format. There is no authentication of its own — access control is the socket permissions plus your policies.

## Request flow (`proxy/proxy.go`)

1. Read the body; determine client IP (socket peer address only; `X-Forwarded-For`/`X-Real-Ip` are ignored because clients can forge them; Unix socket clients show up as `@`).
2. Build OPA input (below). If `Content-Type` is `application/json` the body is validated and parsed (400 on invalid JSON, duplicate keys, or non-canonical key spelling, see "Request body checks"); otherwise `body` stays a raw string. The query string is passed as `query` (`{"fromImage": ["alpine"]}`).
3. Evaluate `data.policies.allow` and `data.policies.reason`. Deny → HTTP 403 with the reason; evaluation error → 500. No result = deny.
4. If isolation is on: transform the request and check resource ownership (403 otherwise).
5. Forward via `httputil.ReverseProxy` to the Docker socket (HTTP upgrades for attach/exec are handled natively).

### OPA input

```json
{
  "method": "POST",
  "api_ver": "v1.44",
  "path": "/containers/create",
  "query": { "fromImage": ["alpine"] },
  "body": { "...parsed JSON..." },
  "headers": { "Content-Type": "application/json" },
  "client_ip": "127.0.0.1"
}
```

The version prefix is stripped from `path`, so policies match clean paths like `/containers/create`.

## Request body checks (`bodycheck/`)

The policies must see the same body the Docker daemon acts on. The daemon decodes JSON with Go's `encoding/json`, which matches keys **case-insensitively** (`{"hostconfig":{"privileged":true}}` sets `HostConfig.Privileged`) and **merges duplicate keys** (`{"HostConfig":{"Privileged":true},"HostConfig":{}}` is privileged). A rule reading `input.body.HostConfig.Privileged` would miss both, so such bodies are rejected with `400` instead of being interpreted:

- **Duplicate keys** anywhere in a JSON body.
- **Non-canonical key spelling** on `/containers/create` and network `connect`/`disconnect`: the keys the policies read must be spelled exactly as in the Docker API (`HostConfig`, not `hostconfig`; Unicode case-folding tricks like `HoſtConfig` too). Docker CLI, compose and the SDKs always do.
- **Content-Type** must be `application/json` (any case/charset) for bodies of `/containers/create`, `/commit`, `/networks/create`, `/volumes/create` and network `connect`/`disconnect`, so the body is always parsed the same way.

Map-valued fields (`Labels`, `EndpointsConfig`, `Tmpfs`, …) are opaque: their keys are data, so labels named `type` or `image` are fine, as are unknown fields.

**Writing policies:** a rule may rely on exact key spelling only for fields listed in the schemas in `bodycheck/bodycheck.go`. If you write a rule on another body field, add it there — otherwise it can be bypassed by spelling the key in a different case.

## Policies (`policies/`)

All files are `package policies` and are loaded together, in one module set. Contract: the engine reads `data.policies.allow` (bool) and `data.policies.reason` (string).

**Model: read-only and hardened by default.** A request is allowed only if

1. its operation is *permitted* — by default only `GET`/`HEAD` (minus secrets/configs and websocket attach); write operations belong to named groups you enable in the config, **and**
2. the `denial` set is empty — hardening rules (privileged, host namespaces, dangerous capabilities, bind mounts, …) have no objections.

Denials can't be overridden by any permissive rule; they are relaxed only through the config, which the rules themselves read. This keeps rules independent (no matching on each other's messages). Files are numbered by purpose:

| File | Effect |
|------|--------|
| `00_config.rego` | Config defaults (`default_config`), merge with `data.config`, validation (`config_errors`). |
| `01_framework.rego` | `allow` / `reason`. Don't remove. The only place that defines `allow`. |
| `02_container_security.rego` | Hardening for `/containers/create`: privileged, host network/PID/IPC/userns, host devices (`Devices`, `DeviceCgroupRules`, `DeviceRequests`), privileged `exec`, `VolumesFrom` without full isolation, `SecurityOpt` allowlist (only `no-new-privileges`, `apparmor=docker-default`; any other seccomp/AppArmor/SELinux option needs `unconfined_security`), dangerous `CapAdd` (case and `CAP_` prefix normalized), bind mounts outside allowed prefixes (`Binds` and `Mounts`), volume mounts with driver options (bind bypass), `/volumes/create` with `DriverOpts` or a non-`local` driver (bind-mount bypass via named volumes), unknown mount types, non-JSON body. |
| `03_operations.rego` | The operation allowlist: read-only default plus write groups. With full isolation only reads of isolatable objects are visible (no `/system/df`, `/swarm`, …). |
| `04_images.rego` | `allowed_images`: limit which images may be pulled and run (empty = any). |
| `06_internal_network.rego` | Deny clients outside `allowed_client_cidrs` (Unix-socket clients exempt). |
| `90_policy_test.rego` | `opa test` unit tests. |

### Policy config (`policy:` in config.yaml)

Loaded as `data.config`; see `config.yaml.example` for all options and the full token list.

```yaml
policy:
  allow: [containers_create, containers_control, containers_delete]  # enable write groups / exempt hardening rules
  allowed_bind_prefixes: ["/dev/", "/temp/agent/"]                   # bind mounts only below these (must start+end with "/")
  allowed_capabilities: [NET_ADMIN]                                  # dangerous caps that may still be added
  allowed_images: ["alpine", "myregistry.local/*"]                   # images that may be pulled/run (default: any)
  allowed_client_cidrs: ["10.0.0.0/8"]                               # default: loopback + RFC1918
```

Every key defaults to the strictest value. Write groups: `containers_create`, `containers_control`, `containers_delete`, `exec`, `build`, `images_pull` (pull only), `images_write` (push/tag/load/commit/prune/delete), `volumes_write`, `networks_write`, `secrets_configs_read`. Unknown keys, unknown `allow` tokens and malformed values make the proxy **refuse to start** (and deny everything if it somehow ran). Denial messages tell you which token or option would relax the rule.

Notes:
- `policies_extra/deny_admin.rego` is **not loaded** by default; it is an optional stricter rule set (denies container lifecycle ops, container creation, all DELETEs). Copy it into the policies directory to enable it. With the read-only default it is mostly redundant.
- Extra policy files can add to `denial` (always safe) or add bodies to `request_permitted` (to enable further endpoints). Do not define `allow`.
- Every `*.rego` file in `policies_path` is loaded, including `*_test.rego`.
- Bind-mount checks are textual: symlinks inside an allowed prefix are not resolved. Only allow prefixes you control.
- Policies and config are read once at startup — restart to apply changes.
- Keep the installed policy files in sync with the binary. The proxy refuses to start if a `policy:` config is given but the policies don't understand it (outdated policy set).
- Test policies: `opa test policies/ -v` (requires the OPA CLI).

## Isolation (`isolation/`)

Optional, so several users/projects can share one Docker daemon. Enable with `isolation.enabled: true` (config) or `-i` / `--isolation-name`. Resources created through the proxy get the label `io.opa-docker-proxy.isolation=<name>` (injected into create bodies, build labels, and — for volumes created implicitly through `HostConfig.Mounts` — the volume options; any client-supplied value of that label is overwritten). Use a **stable** `isolation.name`: resources labelled with another name are invisible/untouchable.

| Mode | Behaviour |
|------|-----------|
| `full` (default) | The client sees a private daemon. Container/volume/network lists and `/events` are filtered by label; every per-resource request — reads included — is checked by inspecting the resource, a mismatch is 403. `exec` into a container requires owning it. Daemon-wide endpoints that can't be filtered (`/system/df`, `/swarm`, …) are hidden by the policies. |
| `writes` | Reads are unrestricted; only requests that change something (and websocket attach) are checked. Prune is scoped by label in both modes. |

In both modes:

- **References.** Container creation can't *reference* resources outside the isolation context: `VolumesFrom`, `container:<id>` network/PID/IPC modes, `Links`, networks (`NetworkMode`, `EndpointsConfig`), named volumes (`Binds`, volume `Mounts`) and the image are checked. `networks/{id}/connect|disconnect`, `commit` and `images/get` check the container/images they name. Built-in networks (`bridge`, `none`, …) are always usable.
- **Volumes are always labelled.** Named volumes that don't exist yet are created by the proxy (with the label) before the container is created, so the daemon never creates unlabelled ones implicitly. Anonymous volumes — single-element `Binds` (`"/data"`), `Volumes`, and volumes declared by the image (`VOLUME`) — are turned into labelled volume mounts (not done together with `VolumesFrom`; volumes using a non-`local` driver are labelled through their mount options instead of pre-created).
- **Images have three states.** *Own* — built or committed through the proxy, labelled; fully usable. *Foreign* — labelled for another isolation name; can't be used, inspected, exported or listed (`full`). *Shared* — unlabelled, i.e. pulled or public (a pull can't carry a label); usable, but read-only: can't be deleted, pushed or tagged through the proxy, so `images_write` only affects own images. **If `policy.allowed_images` is set, shared images are masked by it:** a shared image is only visible (list, inspect, history, export) and usable (container create) if its typed name or one of its repo tags/digests matches. So a client sees its own images plus the allowed ones — images pulled by others and not on the list don't exist for it. Matching an image *ID* works through its tags. `docker commit` labels the new image and requires an own container.
- `policy.allowed_images` also controls which images may be pulled and run (policy), and — with isolation — is the mask described above. Own images (built/committed through the proxy) are always usable.

Limitations:
- Without `policy.allowed_images`, pulled (shared) images are visible to every client of the daemon. Set it to mask them (in `full` mode; in `writes` mode reads are open by definition, but creating containers is still restricted).
- Image builds can't be checked for `FROM` of a foreign image.
- Starting the proxy with change-capable `policy.allow` tokens (`containers_control`, `containers_delete`, `exec`, `volumes_write`, `networks_write`, `images_write`) **without** isolation logs a warning: clients could then change objects they didn't create.

To remove the feature: delete `isolation/`, the isolation handling in `main.go`, and the few calls in `proxy.go`.

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
