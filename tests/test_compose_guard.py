import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from textwrap import indent

import yaml

from compose_guard import MAX_BYTES, MAX_DEPTH, MAX_NODES, InputError, assess, read_input


ROOT = Path(__file__).resolve().parents[1]
RISKY = ROOT / "exercises" / "01-risky.fixture.yaml"
HARDENED = ROOT / "exercises" / "02-hardened.fixture.yaml"
BASELINE = {
    "read_only": True,
    "user": "10001:10001",
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
}


def service_document(**changes):
    return yaml.safe_dump({"services": {"worker": BASELINE | changes}})


def codes(text):
    return [finding.code for finding in assess(text)]


def cli(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "compose_guard.py"), *map(str, args)],
        capture_output=True, text=True, timeout=10, check=False,
    )


class PolicyTests(unittest.TestCase):
    def test_minimal_standalone_baseline_passes(self):
        self.assertEqual(assess(service_document()), [])

    def test_default_service_reports_each_missing_control(self):
        self.assertEqual(codes("services: {worker: {}}"), [
            "READ_ONLY", "NONROOT_USER", "DROP_CAPABILITIES", "NO_NEW_PRIVILEGES",
        ])

    def test_privileged_true_and_false(self):
        self.assertEqual(codes(service_document(privileged=True)), ["PRIVILEGED"])
        self.assertEqual(codes(service_document(privileged=False)), [])

    def test_every_host_mode_is_attributed_to_its_field(self):
        fields = ["network_mode", "pid", "ipc", "uts", "cgroup", "userns_mode"]
        findings = assess(service_document(**dict.fromkeys(fields, "host")))
        self.assertEqual([(f.code, f.field) for f in findings],
                         [("HOST_NAMESPACE", field) for field in fields])

    def test_non_host_modes_are_not_flagged(self):
        self.assertEqual(codes(service_document(network_mode="none", ipc="private")), [])

    def test_explicit_device_grants_are_flagged_per_field(self):
        for fields in ({"devices": ["example.invalid/lab=sample"]},
                       {"device_cgroup_rules": ["c 240:0 r"]}):
            with self.subTest(fields=fields):
                findings = assess(service_document(**fields))
                self.assertEqual([(f.code, f.field) for f in findings],
                                 [("DEVICE_ACCESS", next(iter(fields)))])
        self.assertEqual(assess(service_document(devices=[], device_cgroup_rules=[])), [])

    def test_sensitive_bind_flags_ro_and_normalizes_paths(self):
        findings = assess(service_document(volumes=[
            "/sys/kernel:/reference:ro",
            {"type": "bind", "source": "/var/tmp/../lib//docker/",
             "target": "/reference", "read_only": True},
            "/:/reference:ro",
            "/var/lib:/reference:ro",
            "//dev/shm:/reference:ro",
        ]))
        self.assertEqual([(f.code, f.field) for f in findings],
                         [("SENSITIVE_BIND", f"volumes[{i}]") for i in range(5)])

    def test_socket_detection_checks_source_or_target_basename(self):
        findings = assess(service_document(volumes=[
            "./docker.sock:/reference:ro",
            {"type": "bind", "source": "/srv/example/data", "target": "/work/podman.sock",
             "read_only": True},
            "/srv/example/containerd.sock:/reference:ro",
        ]))
        self.assertEqual([f.code for f in findings], ["SENSITIVE_BIND"] * 3)
        self.assertTrue(all("socket" in f.message for f in findings))

    def test_bind_access_controls_in_both_syntaxes(self):
        long_bind = {"type": "bind", "source": "./sample", "target": "/reference"}
        for mount, expected in (
            ("./sample:/reference:ro,Z", []),
            ("./sample:/reference", ["WRITABLE_BIND"]),
            ("./sample:/reference:rw,z", ["WRITABLE_BIND"]),
            (long_bind | {"read_only": True}, []),
            (long_bind | {"read_only": False}, ["WRITABLE_BIND"]),
            (long_bind, ["WRITABLE_BIND"]),
        ):
            with self.subTest(mount=mount):
                findings = assess(service_document(volumes=[mount]))
                self.assertEqual([(f.code, f.field) for f in findings],
                                 [(code, "volumes[0]") for code in expected])

    def test_writable_sensitive_bind_reports_both_policy_failures(self):
        self.assertEqual(codes(service_document(volumes=["/etc:/reference:rw"])),
                         ["SENSITIVE_BIND", "WRITABLE_BIND"])

    def test_mount_kinds_and_path_boundaries(self):
        text = service_document(volumes=[
            "/etc-backup:/ref:ro", "./sample/config:/example:ro", "/var/lib/docker-old:/archive:ro",
            "docs:/docs:ro", "/anonymous", {"type": "volume", "source": "cache", "target": "/cache"},
            {"type": "tmpfs", "target": "/tmp"},
        ]) + "volumes: {docs: null, cache: {driver: local}}\n"
        self.assertEqual(assess(text), [])

    def test_uid_and_gid_numeric_boundaries(self):
        for value in (0, -1, "000", "001:000", "0:1", "worker", "1:workers", 4294967295,
                      "1:4294967295", "9" * 5000):
            with self.subTest(value=str(value)[:30]):
                self.assertEqual(codes(service_document(user=value)), ["NONROOT_USER"])
        for value in (1, 4294967294, "00001:00002", "4294967294:4294967294"):
            with self.subTest(value=value):
                self.assertEqual(assess(service_document(user=value)), [])

    def test_unquoted_uid_gid_is_not_a_base_60_integer(self):
        for pair, expected in (("1:0", ["NONROOT_USER"]), ("1:2", [])):
            text = (
                "services:\n  worker:\n    read_only: true\n    cap_drop: [ALL]\n"
                f"    security_opt: ['no-new-privileges:true']\n    user: {pair}\n"
            )
            self.assertEqual(codes(text), expected)

    def test_capability_additions_are_flagged_even_with_drop_all(self):
        self.assertEqual(codes(service_document(cap_add=["NET_BIND_SERVICE"])), ["ADD_CAPABILITIES"])
        self.assertEqual(codes(service_document(cap_drop=["NET_RAW"])), ["DROP_CAPABILITIES"])

    def test_no_new_privileges_requires_one_explicit_true(self):
        for options in ([], ["no-new-privileges"], ["no-new-privileges:false"],
                        ["no-new-privileges:true", "no-new-privileges=false"],
                        ["no-new-privileges:true"] * 2):
            with self.subTest(options=options):
                self.assertEqual(codes(service_document(security_opt=options)), ["NO_NEW_PRIVILEGES"])
        self.assertEqual(assess(service_document(security_opt=["no-new-privileges=true"])), [])

    def test_all_services_are_checked_even_if_profile_is_inactive(self):
        text = "services:\n  z: {}\n  a:\n" + indent("profiles: [optional]\n", "    ")
        findings = assess(text)
        self.assertEqual([f.service for f in findings], ["a"] * 4 + ["z"] * 4)


class InputTests(unittest.TestCase):
    def test_invalid_documents_never_pass(self):
        for text in ("", "[]", "services: {}", "services: null", "services: {w: null}",
                     "services: [{w: {}}]", "services: {\"bad name\": {}}"):
            with self.subTest(text=text), self.assertRaises(InputError):
                assess(text)

    def test_yaml_syntax_errors_are_located_without_echoing_input(self):
        with self.assertRaisesRegex(InputError, r"invalid YAML at line \d+, column \d+") as ctx:
            assess("services: [\"private-data\"")
        self.assertNotIn("private-data", str(ctx.exception))

    def test_ambiguous_yaml_is_rejected_recursively(self):
        cases = {
            "services: {}\nservices: {w: {}}": "duplicate YAML key",
            "services: {w: {privileged: true, privileged: false}}": "duplicate YAML key",
            "services: &svc {w: {}}": "anchors and aliases",
            "services: *svc": "anchors and aliases",
            "services: {w: {<<: {privileged: true}}}": "mapping keys must be strings",
            "services: {w: !!map {}}": "explicit YAML tags",
            "services: {w: {}}\n---\nservices: {w: {}}": "one document",
        }
        for text, reason in cases.items():
            with self.subTest(text=text), self.assertRaisesRegex(InputError, reason):
                assess(text)

    def test_nesting_boundary(self):
        def nested(levels):
            return "services: {worker: {}}\nx-data: " + "[" * levels + "0" + "]" * levels

        self.assertEqual(len(assess(nested(MAX_DEPTH - 2))), 4)
        with self.assertRaisesRegex(InputError, "nesting exceeds"):
            assess(nested(MAX_DEPTH - 1))

    def test_node_limit_counts_shallow_content_even_in_ignored_extensions(self):
        def wide(items):
            return "services: {worker: {}}\nx-samples: [" + ",".join(["0"] * items) + "]\n"

        # The document uses seven nodes before counting the sequence items.
        limit = MAX_NODES - 7
        self.assertEqual(len(assess(wide(limit))), 4)
        over_limit = wide(limit + 1)
        self.assertLess(len(over_limit.encode("utf-8")), MAX_BYTES)
        with self.assertRaisesRegex(InputError, rf"line 2: YAML document exceeds {MAX_NODES} nodes"):
            assess(over_limit)
        self.assertEqual(assess(service_document()), [])

    def test_interpolation_and_dollar_escapes_are_not_evaluated(self):
        for expression in ("${REGISTRY}", "$REGISTRY", "$${REGISTRY}"):
            with self.subTest(expression=expression), self.assertRaisesRegex(InputError, "interpolation"):
                assess(service_document(image=expression))
        self.assertEqual(assess(service_document() + "# ${COMMENT}\n"), [])

    def test_external_config_is_not_resolved(self):
        cases = [
            (service_document() + "include: [missing.yml]", "document.include"),
            (service_document(extends={"file": "missing.yml", "service": "example"}), "extends"),
            (service_document(volumes_from=["another"]), "volumes_from"),
            (service_document() + "volumes: {data: {external: true}}", "default local"),
            (service_document() + "volumes: {data: {driver: example}}", "default local"),
            (service_document() + "volumes: {data: {name: preexisting}}", "default local"),
            (service_document() + "volumes: {data: {driver_opts: {o: bind}}}", "default local"),
        ]
        for text, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(InputError, reason):
                assess(text)

    def test_invalid_inspected_field_types(self):
        for changes in ({"privileged": "true"}, {"read_only": 1}, {"user": True}, {"user": None},
                        {"ipc": []}, {"cap_drop": "ALL"}, {"cap_add": [None]},
                        {"security_opt": {"no-new-privileges": True}}, {"volumes": "cache:/cache"}):
            with self.subTest(changes=changes), self.assertRaisesRegex(InputError, r"services\.worker\."):
                assess(service_document(**changes))
        with self.assertRaisesRegex(InputError, "expected a boolean"):
            assess("services: {worker: {privileged: yes}}")

    def test_device_grants_require_lists_of_strings(self):
        for field in ("devices", "device_cgroup_rules"):
            for value, reason in (("example", "expected a list"), ([None], "expected a nonempty")):
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    InputError, rf"services\.worker\.{field}.*: {reason}"
                ):
                    assess(service_document(**{field: value}))

    def test_invalid_or_unsupported_mounts(self):
        for mount in ("name:relative", "/source:/target:bogus", "~/data:/target", "C:\\data:/target",
                      ":/target", 42, {"type": "image", "target": "/mnt"},
                      {"type": "bind", "target": "/mnt"}, {"type": "bind", "source": "not/a/path"},
                      {"type": "tmpfs", "source": "name", "target": "/mnt"}):
            with self.subTest(mount=mount), self.assertRaisesRegex(InputError, r"volumes\[0\]"):
                assess(service_document(volumes=[mount]))

    def test_ambiguous_mount_access_modes_are_rejected(self):
        for options in ("ro,rw", "rw,ro", "ro,ro"):
            with self.subTest(options=options), self.assertRaisesRegex(InputError, "at most one"):
                assess(service_document(volumes=[f"./sample:/reference:{options}"]))
        for value in (None, "true", 1):
            mount = {"type": "bind", "source": "./sample", "target": "/reference", "read_only": value}
            with self.subTest(value=value), self.assertRaisesRegex(
                InputError, r"volumes\[0\]\.read_only: expected a boolean"
            ):
                assess(service_document(volumes=[mount]))

    def test_fixture_cannot_be_combined_with_services(self):
        with self.assertRaisesRegex(InputError, "fixture must contain only"):
            assess("x-lab-services: {w: {}}\nservices: {w: {}}")

    def test_byte_limit_and_utf8(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            path = Path(folder) / "input.yaml"
            path.write_bytes(b"#" + b" " * (MAX_BYTES - 1))
            self.assertEqual(len(read_input(path)), MAX_BYTES)
            path.write_bytes(b" " * (MAX_BYTES + 1))
            with self.assertRaisesRegex(InputError, "input exceeds"):
                read_input(path)
            path.write_bytes(b"\xff")
            with self.assertRaisesRegex(InputError, "must be UTF-8"):
                read_input(path)


class CLITests(unittest.TestCase):
    def test_bundled_fixtures_have_no_startable_services(self):
        for path in (RISKY, HARDENED):
            with self.subTest(path=path):
                fixture = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertEqual(set(fixture), {"x-lab-services"})
                for service in fixture["x-lab-services"].values():
                    self.assertTrue({"image", "build", "extends"}.isdisjoint(service))

    def test_risky_fixture_exit_1_and_expected_findings(self):
        result = cli(RISKY)
        self.assertEqual((result.returncode, result.stderr), (1, ""))
        lines = result.stdout.splitlines()
        self.assertEqual([line.split()[0] for line in lines[:-1]], [
            "PRIVILEGED", "HOST_NAMESPACE", "HOST_NAMESPACE", "SENSITIVE_BIND", "SENSITIVE_BIND",
            "READ_ONLY", "NONROOT_USER", "DROP_CAPABILITIES", "NO_NEW_PRIVILEGES",
        ])
        self.assertEqual(lines[-1], "9 finding(s).")

    def test_hardened_fixture_exit_0(self):
        result = cli(HARDENED)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "0 finding(s).\n", ""))

    def test_json_clean_report(self):
        result = cli("--format", "json", HARDENED)
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        self.assertEqual(json.loads(result.stdout), {"schema_version": 1, "findings": []})

    def test_json_is_deterministic_in_service_and_policy_order(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            observations = []
            for index, services in enumerate(("{z: {}, a: {}}", "{a: {}, z: {}}")):
                path = Path(folder) / f"input-{index}.yaml"
                path.write_text(f"x-lab-services: {services}\n", encoding="utf-8")
                result = cli(path, "--format", "json")
                self.assertEqual((result.returncode, result.stderr), (1, ""))
                observations.append(result.stdout)
        first, second = observations
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))
        report = json.loads(first)
        self.assertEqual(set(report), {"schema_version", "findings"})
        self.assertEqual(report["schema_version"], 1)
        expected = [
            ("READ_ONLY", "read_only"), ("NONROOT_USER", "user"),
            ("DROP_CAPABILITIES", "cap_drop"), ("NO_NEW_PRIVILEGES", "security_opt"),
        ]
        self.assertEqual([
            (record["service"], record["code"], record["field"]) for record in report["findings"]
        ], [(service, code, field) for service in ("a", "z") for code, field in expected])
        for record in report["findings"]:
            self.assertEqual(set(record), {"code", "service", "field", "message"})
            self.assertTrue(record["message"])

    def test_read_and_parse_errors_exit_2_without_findings(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            bad = Path(folder) / "bad.yaml"
            bad.write_text("services: {a: {}, z: {read_only: 'no'}}", encoding="utf-8")
            for output_format in ("text", "json"):
                for path in (bad, Path(folder), Path(folder) / "missing.yaml"):
                    with self.subTest(path=path, output_format=output_format):
                        result = cli(path, "--format", output_format)
                        self.assertEqual((result.returncode, result.stdout), (2, ""))
                        self.assertTrue(result.stderr.startswith("Input error: "))
