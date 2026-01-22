"""Offline policy checks for a standalone Linux Compose document."""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml
from yaml.events import AliasEvent, ScalarEvent
from yaml.nodes import MappingNode

MAX_BYTES = 256 * 1024
MAX_DEPTH = 32
FIXTURE_KEY = "x-lab-services"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
ID = re.compile(r"[0-9]+(?::[0-9]+)?\Z")
MAX_LINUX_ID = 2**32 - 2  # The all-ones value is reserved.
INTERPOLATION = re.compile(r"\$(?:[{$]|[A-Za-z_])")
HOST_MODES = ("network_mode", "pid", "ipc", "uts", "cgroup", "userns_mode")
SENSITIVE_TREES = (
    "/boot", "/dev", "/etc", "/proc", "/root", "/run", "/sys",
    "/var/lib/docker", "/var/run",
)
RUNTIME_SOCKETS = {"docker.sock", "containerd.sock", "podman.sock"}
MOUNT_OPTIONS = {
    "ro", "rw", "z", "Z", "private", "rprivate", "shared", "rshared",
    "slave", "rslave", "nocopy", "cached", "delegated", "consistent",
}


class InputError(ValueError):
    """The input cannot be assessed under the documented subset."""


class StaticLoader(yaml.SafeLoader):
    """Reject YAML features that obscure the literal configuration."""

    yaml_implicit_resolvers = {
        first: [(tag, pattern) for tag, pattern in entries
                if tag not in ("tag:yaml.org,2002:bool", "tag:yaml.org,2002:int")]
        for first, entries in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    depth = 0

    def compose_node(self, parent, index):
        event = self.peek_event()
        line = event.start_mark.line + 1
        if isinstance(event, AliasEvent) or event.anchor is not None:
            raise InputError(f"line {line}: YAML anchors and aliases are unsupported")
        if event.tag is not None:
            raise InputError(f"line {line}: explicit YAML tags are unsupported")
        if isinstance(event, ScalarEvent) and INTERPOLATION.search(event.value):
            raise InputError(f"line {line}: Compose interpolation and dollar escapes are unsupported")
        if self.depth >= MAX_DEPTH:
            raise InputError(f"line {line}: YAML nesting exceeds {MAX_DEPTH} levels")
        self.depth += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, MappingNode):
            return super().construct_mapping(node, deep=deep)
        result = {}
        for key_node, value_node in node.value:
            line = key_node.start_mark.line + 1
            if key_node.tag != "tag:yaml.org,2002:str":
                raise InputError(f"line {line}: YAML mapping keys must be strings (no merge keys)")
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise InputError(f"line {line}: duplicate YAML key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


StaticLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), "tTfF"
)
# In particular, do not interpret unquoted UID:GID pairs as YAML 1.1 base-60 integers.
StaticLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"^[-+]?(?:0|[1-9][0-9]*)$"), "-+0123456789"
)


@dataclass(frozen=True)
class Finding:
    code: str
    service: str
    field: str
    message: str


def mapping(value, field: str) -> dict:
    if not isinstance(value, dict):
        raise InputError(f"{field}: expected a mapping")
    return value


def string(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise InputError(f"{field}: expected a nonempty single-line string")
    return value


def name(value, field: str) -> str:
    if not NAME.fullmatch(value):
        raise InputError(f"{field}: expected an alphanumeric name (also allows '.', '_' and '-')")
    return value


def boolean(service: dict, field: str, location: str) -> bool:
    value = service.get(field, False)
    if type(value) is not bool:
        raise InputError(f"{location}.{field}: expected a boolean (true or false)")
    return value


def sequence(service: dict, field: str, location: str) -> list:
    value = service.get(field, [])
    if not isinstance(value, list):
        raise InputError(f"{location}.{field}: expected a list")
    return value


def strings(service: dict, field: str, location: str) -> list[str]:
    return [string(item, f"{location}.{field}[{i}]")
            for i, item in enumerate(sequence(service, field, location))]


def bind_paths(value, field: str) -> tuple[str, str] | None:
    """Validate a supported mount entry and return paths for host binds only."""
    if isinstance(value, str):
        parts = string(value, field).split(":")
        if len(parts) > 3 or (len(parts) > 1 and not parts[0]):
            raise InputError(f"{field}: expected target or source:target[:options]")
        if len(parts) == 3 and not set(parts[2].split(",")) <= MOUNT_OPTIONS:
            raise InputError(f"{field}: unsupported short mount options")
        source, target = (None, parts[0]) if len(parts) == 1 else parts[:2]
        kind = "bind" if source is not None and is_host_path(source) else "volume"
    else:
        entry = mapping(value, field)
        kind = entry.get("type")
        if kind not in ("bind", "volume", "tmpfs"):
            raise InputError(f"{field}.type: expected bind, volume or tmpfs")
        source, target = entry.get("source"), entry.get("target")
        if "source" in entry:
            string(source, f"{field}.source")

    if not string(target, f"{field}.target").startswith("/"):
        raise InputError(f"{field}.target: expected an absolute Linux path")
    if kind == "bind":
        if source is None or not is_host_path(source):
            raise InputError(f"{field}.source: expected an absolute or dot-relative host path")
        return source, target
    if kind == "tmpfs" and source is not None:
        raise InputError(f"{field}.source: tmpfs must not have a source")
    if source is not None:
        name(source, f"{field}.source")
    return None


def is_host_path(path: str) -> bool:
    return path in (".", "..") or path.startswith(("/", "./", "../"))


def sensitive_bind(source: str, target: str) -> str | None:
    host = posixpath.normpath(source)
    container = posixpath.normpath(target)
    if any(posixpath.basename(path) in RUNTIME_SOCKETS for path in (host, container)):
        return "Runtime socket bind; remove it and use a narrower service interface."
    if not host.startswith("/"):
        return None
    host = "/" + host.lstrip("/")
    if host == "/" or any(
        host == tree or host.startswith(tree + "/") or tree.startswith(host + "/")
        for tree in SENSITIVE_TREES
    ):
        return "Host bind overlaps a sensitive path; remove it or use a narrowly scoped volume."
    return None


def nonroot_user(value, location: str) -> bool:
    if type(value) is int:
        return 0 < value <= MAX_LINUX_ID
    value = string(value, f"{location}.user")
    if not ID.fullmatch(value):
        return False
    ids = [part.lstrip("0") for part in value.split(":")]
    return all(0 < len(part) <= 10 and int(part) <= MAX_LINUX_ID for part in ids)


def check_service(service_name: str, raw: object, location: str) -> list[Finding]:
    service = mapping(raw, location)
    for field in ("extends", "volumes_from"):
        if field in service:
            raise InputError(f"{location}.{field}: inherited configuration is unsupported")
    findings = []

    def add(code: str, field: str, message: str) -> None:
        findings.append(Finding(code, service_name, field, message))

    if boolean(service, "privileged", location):
        add("PRIVILEGED", "privileged", "Disable privileged mode to keep container isolation controls.")

    for field in HOST_MODES:
        if field in service and string(service[field], f"{location}.{field}") == "host":
            add("HOST_NAMESPACE", field, "Remove host mode to preserve namespace isolation.")

    for index, volume in enumerate(sequence(service, "volumes", location)):
        field = f"volumes[{index}]"
        paths = bind_paths(volume, f"{location}.{field}")
        if paths is not None and (reason := sensitive_bind(*paths)) is not None:
            add("SENSITIVE_BIND", field, reason)

    if not boolean(service, "read_only", location):
        add("READ_ONLY", "read_only", "Set read_only: true and allow writes only where needed.")
    if not nonroot_user(service.get("user", "0"), location):
        add("NONROOT_USER", "user", "Set an explicit nonzero numeric UID and, if supplied, nonzero GID.")
    if "ALL" not in strings(service, "cap_drop", location):
        add("DROP_CAPABILITIES", "cap_drop", "Drop all Linux capabilities with cap_drop: [ALL].")
    if strings(service, "cap_add", location):
        add("ADD_CAPABILITIES", "cap_add", "Remove capability additions for this restrictive baseline.")

    nnp = []
    for option in strings(service, "security_opt", location):
        key, _, value = option.replace("=", ":", 1).partition(":")
        if key.strip() == "no-new-privileges":
            nnp.append(value if key == "no-new-privileges" else None)
    if nnp != ["true"]:
        add("NO_NEW_PRIVILEGES", "security_opt", 'Set one explicit "no-new-privileges:true" option.')
    return findings


def assess(text: str) -> list[Finding]:
    """Assess one YAML document, raising InputError for unsupported input."""
    try:
        document = yaml.load(text, Loader=StaticLoader)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise InputError(f"invalid YAML{where}; expected one document") from None
    except yaml.YAMLError:
        raise InputError("invalid YAML; expected one document") from None
    except InputError:
        raise
    except ValueError:
        raise InputError("invalid or out-of-range YAML scalar") from None

    document = mapping(document, "document")
    if "include" in document:
        raise InputError("document.include: external configuration is unsupported")
    root = FIXTURE_KEY if FIXTURE_KEY in document else "services"
    if root == FIXTURE_KEY and set(document) != {FIXTURE_KEY}:
        raise InputError(f"{FIXTURE_KEY}: fixture must contain only the {FIXTURE_KEY} key")

    # Local volumes with driver options can mask a host bind; don't grade them as safe.
    for volume in mapping(document.get("volumes", {}), "document.volumes").values():
        if volume is not None:
            volume = mapping(volume, "document.volumes entry")
            if set(volume) - {"labels", "driver", "driver_opts", "external"} or (
                volume.get("driver", "local") != "local"
                or volume.get("driver_opts", {}) != {} or volume.get("external", False) is not False
            ):
                raise InputError("document.volumes: only default local volume definitions are supported")

    services = mapping(document.get(root), root)
    if not services:
        raise InputError(f"{root}: expected at least one service")
    findings = []
    for service_name in sorted(services):
        name(service_name, root)
        findings.extend(check_service(service_name, services[service_name], f"{root}.{service_name}"))
    return findings


def read_input(path: Path) -> str:
    try:
        if not path.is_file():
            raise InputError("expected a readable regular file")
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
    except OSError as exc:
        raise InputError(f"could not read file: {exc.strerror}") from None
    if len(data) > MAX_BYTES:
        raise InputError(f"input exceeds {MAX_BYTES} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("input must be UTF-8") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="standalone Compose YAML file or inert lab fixture")
    args = parser.parse_args(argv)
    try:
        findings = assess(read_input(args.file))
    except InputError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    for result in findings:
        print(f"{result.code} {result.service}.{result.field}: {result.message}")
    print(f"{len(findings)} finding(s).")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
