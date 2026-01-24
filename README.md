# Docker Sec Labs

Review Docker Compose hardening decisions without starting containers. The checker reads one local YAML file and reports which policy rule failed, where it failed, and what to change. The two lab fixtures store synthetic settings under `x-lab-services` and contain no deployable services.

## Quickstart

Use Python 3.10 or newer and PyYAML 6.0.3, the only dependency. If PyYAML is already available at that version, skip installation. Otherwise, from this repository:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

For offline installation, use `python -m pip install --no-index --find-links /path/to/local/wheels -r requirements.txt` with a compatible PyYAML 6.0.3 wheel already available. Checks and tests do not need a network connection or a Docker daemon.

```sh
python3 compose_guard.py exercises/01-risky.fixture.yaml      # 9 findings, exit 1
python3 compose_guard.py exercises/02-hardened.fixture.yaml   # 0 findings, exit 0
python3 compose_guard.py ./compose.yaml                       # optional: your own standalone file
```

Example finding:

```text
SENSITIVE_BIND report-worker.volumes[1]: Runtime socket bind; remove it and use a narrower service interface.
```

| Exit | Meaning |
| --- | --- |
| `0` | No findings under this policy. |
| `1` | One or more findings; printed to stdout, ordered by service name and policy rule. |
| `2` | Invalid invocation, unreadable file, invalid input, or unsupported configuration; see stderr. No partial results are printed. |

## Exercises

1. **Review the risky fixture.** Open [`exercises/01-risky.fixture.yaml`](exercises/01-risky.fixture.yaml). Find the broad privilege grant, two host namespace settings, and two sensitive binds. Predict the four recommended controls that are absent or ineffective, then compare your review with the nine checker findings. A read-only filesystem bind still exposes its contents; a read-only socket mount does not limit the socket API to read-only operations.
2. **Compare the hardened reference.** In [`exercises/02-hardened.fixture.yaml`](exercises/02-hardened.fixture.yaml), host modes and sensitive mounts are gone. The worker has an explicit UID/GID, no added capabilities, and a read-only root filesystem with a separate `/tmp` mount. Compare and check the files statically:

   ```sh
   diff -u exercises/01-risky.fixture.yaml exercises/02-hardened.fixture.yaml  # 1 means different
   python3 compose_guard.py exercises/02-hardened.fixture.yaml               # 0 findings
   ```

   Think through the application tradeoffs: which directories actually need writes, and do their permissions match the selected UID/GID? The checker does not answer either question.

## What the checker enforces

| Finding | Rule |
| --- | --- |
| `PRIVILEGED` | `privileged` must be absent or `false`. |
| `HOST_NAMESPACE` | `network_mode`, `pid`, `ipc`, `uts`, `cgroup`, and `userns_mode` cannot be the literal `host`. Each host setting gets its own finding. |
| `DEVICE_ACCESS` | Leave `devices` and `device_cgroup_rules` absent or empty. Each nonempty field gets a finding regardless of the requested permissions. |
| `SENSITIVE_BIND` | A bind source must not be `/` or overlap `/boot`, `/dev`, `/etc`, `/proc`, `/root`, `/run`, `/sys`, `/var/lib/docker`, or `/var/run`. The rule flags ancestors and descendants on path-component boundaries. It also flags a bind when the source or target basename is `docker.sock`, `containerd.sock`, or `podman.sock`. Read-only binds are checked too. |
| `WRITABLE_BIND` | Request `ro` in short syntax or `read_only: true` in long syntax for host bind mounts. Omitted access modes are writable. This rule is independent of the root filesystem setting and of sensitive path checks; named volumes and tmpfs are not host binds. |
| `READ_ONLY` | Set `read_only: true`. The rule applies to the root filesystem, not separate mounts. |
| `NONROOT_USER` | Set an explicit numeric UID from 1 to 4294967294. If supplying a GID, use the same range. Quote UID:GID pairs, e.g. `user: "10001:10001"`. The checker cannot verify that a numeric ID exists in the image. |
| `DROP_CAPABILITIES` | Include `ALL` in `cap_drop`. |
| `ADD_CAPABILITIES` | Leave `cap_add` absent or empty for this baseline. |
| `NO_NEW_PRIVILEGES` | Include exactly one explicit `"no-new-privileges:true"` or `"no-new-privileges=true"` in `security_opt`. Bare, false, and duplicate directives do not satisfy the policy. |

## Supported input and limitations

- One UTF-8 YAML file up to 256 KiB and 32 nested YAML levels, with a nonempty `services` mapping. Lab fixtures use only the `x-lab-services` top-level key. All services are checked, including those assigned to profiles. The checker rejects duplicate or non-string YAML keys, explicit tags, anchors, aliases, and Compose interpolation/dollar escapes in scalars.
- Review a self-contained Linux configuration. The checker does not load overrides or environment files; `include`, `extends`, and `volumes_from` are rejected. If your actual stack uses dynamically selected configuration, review a separately prepared, resolved static file and account for any inputs it leaves out.
- Supports short Linux mount syntax and long `bind`, `volume`, and `tmpfs` syntax. Repeated or conflicting short access modes (such as `ro,rw`) and non-boolean long `read_only` values are rejected. Named volumes with external declarations, custom names, non-local drivers, or driver options are rejected. Paths are normalized lexically: the checker does not resolve relative binds against the project directory, resolve symlinks, inspect the host, or identify arbitrary socket names.
- This is a targeted policy check, not a Compose schema validator or a production security review. It does not evaluate image defaults, GPU requests (`gpus` or deploy device reservations), service-to-service namespace sharing, other security options, port exposure, or effective filesystem permissions. A zero finding count only means the listed rules passed on the supplied file.

## Verification

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q compose_guard.py tests
python3 -m tabnanny compose_guard.py tests
```

The tests cover valid and rejected inputs, path and numeric boundaries, file limits, fixture safety, and the CLI exit codes. The GitHub Actions workflow runs tests and byte-compilation on pushes and pull requests with read-only repository permissions.

## License and timeline

Licensed under [MIT](LICENSE). The January 2026 commit timeline is illustrative and is not evidence of activity on those dates.
