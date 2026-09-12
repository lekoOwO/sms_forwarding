import hashlib
import json
import os
import re
import shlex
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = ROOT / "firmware-version.json"
GENERATOR = ROOT / "scripts" / "generate-firmware-version.py"
HEADER = ROOT / "components" / "idf_config" / "include" / "firmware_version_generated.h"
SIGNER = ROOT / "scripts" / "sign-ota-release.py"
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"

ACTION_PINS = {
    "actions/checkout": ("de0fac2e4500dabe0009e67214ff5f5447ce83dd", "v6.0.2"),
    "actions/setup-node": ("48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e", "v6.4.0"),
    "actions/upload-artifact": ("ea165f8d65b6e75b540449e92b4886f43607fa02", "v4.6.2"),
    "actions/download-artifact": ("d3f86a106a0bac45b974a628896c90dbdf5c8093", "v4.3.0"),
}
IDF_IMAGE = "espressif/idf@sha256:e3d941cb983e028aad1e2f5ecb2837254e467f2b71f3e0af67e7337bd27ae177"


def yaml_node(text: str, indent: int, key: str) -> tuple[str, str]:
    """Read one mapping node from the small workflow subset used by this repository."""
    lines = text.splitlines()
    prefix = " " * indent + key + ":"
    for index, line in enumerate(lines):
        if not line.startswith(prefix) or line[: len(prefix)] != prefix:
            continue
        if line[len(prefix):] and not line[len(prefix):].startswith((" ", "\t")):
            continue
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if candidate.strip() and len(candidate) - len(candidate.lstrip(" ")) <= indent:
                break
            end += 1
        raw = line[len(prefix):].strip()
        children = "\n".join(lines[index + 1:end])
        if raw in (">", ">-"):
            return " ".join(child.strip() for child in lines[index + 1:end] if child.strip()), children
        if raw in ("|", "|-"):
            margin = " " * (indent + 2)
            return "\n".join(
                child[len(margin):] if child.startswith(margin) else child
                for child in lines[index + 1:end]
            ) + "\n", children
        value = raw.split(" #", 1)[0].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        return value, children
    raise AssertionError(f"missing YAML node at indent {indent}: {key}")


def load_workflow() -> dict[str, object]:
    text = WORKFLOW.read_text(encoding="utf-8")
    _, permissions_block = yaml_node(text, 0, "permissions")
    permissions = {"contents": yaml_node(permissions_block, 2, "contents")[0]}
    jobs: dict[str, object] = {}
    for job_name in ("build", "prerelease", "release"):
        _, job = yaml_node(text, 2, job_name)
        parsed: dict[str, object] = {}
        for field in ("if", "environment", "container"):
            try:
                parsed[field] = yaml_node(job, 4, field)[0]
            except AssertionError:
                pass
        _, job_permissions = yaml_node(job, 4, "permissions")
        parsed["permissions"] = {"contents": yaml_node(job_permissions, 6, "contents")[0]}

        step_starts = [
            index for index, line in enumerate(job.splitlines())
            if line.startswith("      - name:")
        ]
        steps = []
        job_lines = job.splitlines()
        for position, start in enumerate(step_starts):
            end = step_starts[position + 1] if position + 1 < len(step_starts) else len(job_lines)
            step_text = "\n".join(job_lines[start:end])
            step: dict[str, str] = {"name": job_lines[start].split(":", 1)[1].strip()}
            for field in ("if", "uses", "run"):
                try:
                    step[field] = yaml_node(step_text, 8, field)[0]
                except AssertionError:
                    pass
            steps.append(step)
        parsed["steps"] = steps
        jobs[job_name] = parsed
    return {"permissions": permissions, "jobs": jobs}


def named_step(workflow: dict[str, object], job: str, name: str) -> dict[str, object]:
    for step in workflow["jobs"][job]["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"missing {job} step: {name}")


def condition_matches(condition: str, **context: str) -> bool:
    values = {
        "github.event_name": context["event"],
        "github.ref": context["ref"],
        "github.base_ref": context.get("base", ""),
        "needs.build.outputs.ota_runtime_ready": context.get("ota_ready", "false"),
    }

    def starts_with(match: re.Match[str]) -> str:
        return str(values[match.group(1)].startswith(match.group(2)))

    def equals(match: re.Match[str]) -> str:
        return str(values[match.group(1)] == match.group(2))

    expression = re.sub(
        r"startsWith\((github\.(?:event_name|ref|base_ref)),\s*'([^']*)'\)",
        starts_with,
        condition,
    )
    expression = re.sub(
        r"(github\.(?:event_name|ref|base_ref)|needs\.build\.outputs\.ota_runtime_ready)\s*==\s*'([^']*)'",
        equals,
        expression,
    )
    expression = expression.replace("&&", " and ").replace("||", " or ")
    expression = " ".join(expression.split())
    if not re.fullmatch(r"(?:(?:True|False|and|or)|[()\s])+", expression):
        raise AssertionError(f"unsupported workflow condition: {condition}")
    return bool(eval(expression, {"__builtins__": {}}, {}))


def run_publish_script(script: str, work: Path, *, release_exists: bool,
                       extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    fake_bin = work / "bin"
    fake_bin.mkdir(exist_ok=True)
    log = work / "gh.log"
    gh = fake_bin / "gh"
    gh.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$GH_LOG\"\n"
        "if [ \"$1 $2\" = 'release view' ]; then [ \"$GH_VIEW_EXISTS\" = 1 ]; exit; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    env = os.environ.copy()
    env.update(extra_env)
    env.update({
        "PATH": f"{fake_bin}:{env['PATH']}",
        "GH_LOG": str(log),
        "GH_VIEW_EXISTS": "1" if release_exists else "0",
    })
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
    )


def run_tag_gate(previous_version: str, current_version: str) -> subprocess.CompletedProcess[str]:
    """Execute the workflow's release-tag policy in a real temporary Git repository."""
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        (work / "scripts").mkdir()
        (work / "scripts/generate-firmware-version.py").write_bytes(GENERATOR.read_bytes())
        subprocess.run(["git", "init", "-q", "-b", "master"], cwd=work, check=True)
        subprocess.run(["git", "config", "user.name", "Release Test"], cwd=work, check=True)
        subprocess.run(["git", "config", "user.email", "release-test@example.invalid"], cwd=work, check=True)

        version_path = work / "firmware-version.json"
        version_path.write_text(previous_version, encoding="utf-8")
        subprocess.run(["git", "add", "firmware-version.json"], cwd=work, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "previous release"], cwd=work, check=True)
        subprocess.run(["git", "tag", "v1.1.3"], cwd=work, check=True)

        version_path.write_text(current_version, encoding="utf-8")
        subprocess.run(["git", "add", "firmware-version.json"], cwd=work, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "current release"], cwd=work, check=True)
        current_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=work, check=True, capture_output=True, text=True
        ).stdout.strip()
        subprocess.run(["git", "tag", "v1.1.4"], cwd=work, check=True)
        subprocess.run(
            ["git", "update-ref", "refs/remotes/origin/master", current_sha], cwd=work, check=True
        )

        script = named_step(load_workflow(), "build", "Verify release tag")["run"]
        env = os.environ.copy()
        env.update({"GITHUB_REF_NAME": "v1.1.4", "GITHUB_SHA": current_sha})
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", script], cwd=work, env=env,
            capture_output=True, text=True,
        )


def run_branch_counter_gate(previous_version: str | None, current_version: str, *,
                            before: str = "previous", recreate_branch: bool = False,
                            base_sha: bool = False, base_ref: str = ""
                            ) -> subprocess.CompletedProcess[str]:
    """Execute the branch counter policy against real commits and refs."""
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        (work / "scripts").mkdir()
        (work / "scripts/generate-firmware-version.py").write_bytes(GENERATOR.read_bytes())
        subprocess.run(["git", "init", "-q", "-b", "develop"], cwd=work, check=True)
        subprocess.run(["git", "config", "user.name", "Release Test"], cwd=work, check=True)
        subprocess.run(["git", "config", "user.email", "release-test@example.invalid"], cwd=work, check=True)

        if previous_version is None:
            (work / "README").write_text("previous\n", encoding="utf-8")
            subprocess.run(["git", "add", "README"], cwd=work, check=True)
        else:
            (work / "firmware-version.json").write_text(previous_version, encoding="utf-8")
            subprocess.run(["git", "add", "firmware-version.json"], cwd=work, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "previous build"], cwd=work, check=True)
        previous_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=work, check=True, capture_output=True, text=True
        ).stdout.strip()

        (work / "firmware-version.json").write_text(current_version, encoding="utf-8")
        subprocess.run(["git", "add", "firmware-version.json"], cwd=work, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "current build"], cwd=work, check=True)
        current_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=work, check=True, capture_output=True, text=True
        ).stdout.strip()
        if recreate_branch:
            subprocess.run(
                ["git", "update-ref", "refs/remotes/origin/develop", current_sha], cwd=work, check=True
            )

        before_value = {
            "previous": previous_sha,
            "missing": "f" * 40,
            "zero": "0" * 40,
        }[before]
        script = named_step(load_workflow(), "build", "Verify Dev build increased")["run"]
        env = os.environ.copy()
        env.update({
            "BEFORE": before_value,
            "BASE_SHA": previous_sha if base_sha else "",
            "GITHUB_BASE_REF": base_ref,
        })
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", script], cwd=work, env=env,
            capture_output=True, text=True,
        )


class FirmwareVersionTests(unittest.TestCase):
    def test_container_checkout_is_trusted_for_later_git_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            subprocess.run(["git", "init", "-q", str(work)], check=True)
            env = os.environ.copy()
            env.update({
                "GITHUB_WORKSPACE": str(work),
                "GIT_CONFIG_GLOBAL": str(work / "gitconfig"),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
            })
            setup = next((step["run"] for step in load_workflow()["jobs"]["build"]["steps"]
                          if step["name"] == "Trust container checkout"), "")
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", setup + "\ngit status --porcelain"],
                cwd=work, env=env, capture_output=True, text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)

    def test_checked_in_version_source_and_header_are_synchronized(self):
        self.assertTrue(VERSION.exists(), "firmware-version.json is missing")
        self.assertTrue(GENERATOR.exists(), "firmware version generator is missing")
        result = subprocess.run(
            ["python3", str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)

        version = json.loads(VERSION.read_text(encoding="utf-8"))
        self.assertEqual({"releaseVersion": "1.1.4", "devBuild": 21}, version)
        header = HEADER.read_text(encoding="utf-8")
        self.assertIn('#define FIRMWARE_RELEASE_LABEL "1.1.4 (21)"', header)
        self.assertIn('#define FIRMWARE_DEV_BUILD_TEXT "21"', header)

    def test_build_mode_selects_the_public_firmware_version(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            source = work / "version.cpp"
            source.write_text(
                '#include <iostream>\n#include "firmware_version_generated.h"\n'
                'int main() { std::cout << FIRMWARE_DISPLAY_VERSION; }\n',
                encoding="utf-8",
            )
            for release_mode, expected in (("0", "21"), ("1", "1.1.4 (21)")):
                binary = work / f"version-{release_mode}"
                compile_result = subprocess.run(
                    [
                        "g++", "-std=c++17", f"-DFIRMWARE_IS_RELEASE={release_mode}",
                        "-I", str(HEADER.parent), str(source), "-o", str(binary),
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(0, compile_result.returncode, compile_result.stderr)
                result = subprocess.run([str(binary)], capture_output=True, text=True)
                self.assertEqual(expected, result.stdout)

    def test_generator_rejects_invalid_version_source(self):
        self.assertTrue(GENERATOR.exists(), "firmware version generator is missing")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "components/idf_config/include").mkdir(parents=True)
            (root / "scripts/generate-firmware-version.py").write_bytes(GENERATOR.read_bytes())
            (root / "firmware-version.json").write_text(
                '{"releaseVersion":"1.1","devBuild":0}\n', encoding="utf-8"
            )
            result = subprocess.run(
                ["python3", str(root / "scripts/generate-firmware-version.py")],
                cwd=root,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("releaseVersion must be MAJOR.MINOR.PATCH", result.stderr)

    def test_generator_rejects_json_boolean_and_refuses_overflowing_bump(self):
        for source, arguments, expected in (
            ('{"releaseVersion":"1.1.4","devBuild":true}\n', [], "positive 31-bit integer"),
            ('{"releaseVersion":"1.1.4","devBuild":2147483647}\n', ["--bump"], "cannot be increased"),
        ):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "scripts").mkdir()
                (root / "components/idf_config/include").mkdir(parents=True)
                (root / "scripts/generate-firmware-version.py").write_bytes(GENERATOR.read_bytes())
                version_path = root / "firmware-version.json"
                version_path.write_text(source, encoding="utf-8")
                result = subprocess.run(
                    ["python3", str(root / "scripts/generate-firmware-version.py"), *arguments],
                    cwd=root,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertIn(expected, result.stderr)
                self.assertEqual(source, version_path.read_text(encoding="utf-8"))


class OtaSignerTests(unittest.TestCase):
    def test_signer_emits_a_verifiable_smsota_package_and_checks_key_identity(self):
        self.assertTrue(SIGNER.exists(), "OTA release signer is missing")
        firmware = b"native-esp-idf-firmware\x00\x01"
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            private_key = work / "private.pem"
            public_key = work / "public.pem"
            firmware_path = work / "firmware.bin"
            package_path = work / "release.smsota"
            signature_path = work / "signature.bin"
            manifest_path = work / "manifest.json"
            subprocess.run(
                [
                    "openssl", "genpkey", "-algorithm", "EC", "-out", private_key,
                    "-pkeyopt", "ec_paramgen_curve:P-256",
                ],
                check=True,
                capture_output=True,
            )
            key_description = subprocess.run(
                ["openssl", "pkey", "-in", private_key, "-text_pub", "-noout"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("Public-Key: (256 bit)", key_description)
            self.assertIn("ASN1 OID: prime256v1", key_description)
            subprocess.run(
                ["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key],
                check=True,
                capture_output=True,
            )
            public_der = subprocess.run(
                ["openssl", "pkey", "-in", private_key, "-pubout", "-outform", "DER"],
                check=True,
                capture_output=True,
            ).stdout
            fingerprint = hashlib.sha256(public_der).hexdigest()
            firmware_path.write_bytes(firmware)
            result = subprocess.run(
                [
                    "python3", str(SIGNER), str(firmware_path), str(package_path),
                    "--private-key", str(private_key), "--version", "1.1.4",
                    "--counter", "31", "--expected-public-sha256", fingerprint,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)

            omitted_fingerprint = subprocess.run(
                [
                    "python3", str(SIGNER), str(firmware_path), str(work / "unbound.smsota"),
                    "--private-key", str(private_key), "--version", "1.1.4", "--counter", "31",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, omitted_fingerprint.returncode)
            self.assertFalse((work / "unbound.smsota").exists())

            package = package_path.read_bytes()
            self.assertEqual(b"SMSOTA1\n", package[:8])
            manifest_length = struct.unpack(">I", package[8:12])[0]
            manifest = package[12 : 12 + manifest_length]
            signature_offset = 12 + manifest_length
            signature_length = struct.unpack(">H", package[signature_offset : signature_offset + 2])[0]
            signature = package[signature_offset + 2 : signature_offset + 2 + signature_length]
            payload = package[signature_offset + 2 + signature_length :]
            self.assertEqual(firmware, payload)
            self.assertEqual(
                {
                    "format": 1,
                    "releaseCounter": 31,
                    "sha256": hashlib.sha256(firmware).hexdigest(),
                    "size": len(firmware),
                    "target": "esp32c3",
                    "version": "1.1.4",
                },
                json.loads(manifest),
            )
            manifest_path.write_bytes(manifest)
            signature_path.write_bytes(signature)
            verify = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", public_key, "-signature", signature_path, manifest_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, verify.returncode, verify.stderr)

            rejected = subprocess.run(
                [
                    "python3", str(SIGNER), str(firmware_path), str(work / "wrong.smsota"),
                    "--private-key", str(private_key), "--version", "1.1.4",
                    "--counter", "31", "--expected-public-sha256", "0" * 64,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("does not match", rejected.stderr)

            rsa_key = work / "rsa.pem"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", rsa_key],
                check=True,
                capture_output=True,
            )
            rsa_der = subprocess.run(
                ["openssl", "pkey", "-in", rsa_key, "-pubout", "-outform", "DER"],
                check=True,
                capture_output=True,
            ).stdout
            wrong_type = subprocess.run(
                [
                    "python3", str(SIGNER), str(firmware_path), str(work / "rsa.smsota"),
                    "--private-key", str(rsa_key), "--version", "1.1.4", "--counter", "31",
                    "--expected-public-sha256", hashlib.sha256(rsa_der).hexdigest(),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, wrong_type.returncode)
            self.assertIn("P-256", wrong_type.stderr)


class ReleaseWorkflowTests(unittest.TestCase):
    def test_event_matrix_only_publishes_from_automatic_develop_or_tag_pushes(self):
        workflow = load_workflow()
        prerelease = workflow["jobs"]["prerelease"]["if"]
        release = workflow["jobs"]["release"]["if"]
        cases = (
            ("push", "refs/heads/develop", "", "true", True, False),
            ("push", "refs/heads/master", "", "true", False, False),
            ("push", "refs/tags/v1.1.4", "", "true", False, True),
            ("push", "refs/tags/v1.1.4", "", "false", False, False),
            ("workflow_dispatch", "refs/heads/develop", "", "true", False, False),
            ("workflow_dispatch", "refs/tags/v1.1.4", "", "true", False, False),
            ("pull_request", "refs/pull/7/merge", "develop", "true", False, False),
            ("pull_request", "refs/pull/8/merge", "master", "true", False, False),
        )
        for event, ref, base, ready, expected_pre, expected_release in cases:
            with self.subTest(event=event, ref=ref, base=base, ready=ready):
                context = {"event": event, "ref": ref, "base": base, "ota_ready": ready}
                self.assertEqual(expected_pre, condition_matches(prerelease, **context))
                self.assertEqual(expected_release, condition_matches(release, **context))

        monotonic = named_step(workflow, "build", "Verify Dev build increased")["if"]
        for event, ref, base, expected in (
            ("push", "refs/heads/develop", "", True),
            ("push", "refs/heads/master", "", True),
            ("pull_request", "refs/pull/1/merge", "develop", True),
            ("pull_request", "refs/pull/2/merge", "master", True),
            ("workflow_dispatch", "refs/heads/develop", "", False),
            ("push", "refs/tags/v1.1.4", "", False),
        ):
            with self.subTest(monotonic=(event, ref, base)):
                self.assertEqual(expected, condition_matches(
                    monotonic, event=event, ref=ref, base=base, ota_ready="true"
                ))

    def test_release_inputs_permissions_and_immutable_supply_chain_pins(self):
        workflow = load_workflow()
        self.assertEqual("read", workflow["permissions"]["contents"])
        self.assertEqual("read", workflow["jobs"]["build"]["permissions"]["contents"])
        self.assertEqual("release", workflow["jobs"]["release"]["environment"])
        self.assertEqual(IDF_IMAGE, workflow["jobs"]["build"]["container"])
        self.assertIn(
            "python3 -m unittest tools/test_firmware_release.py",
            "\n".join(step.get("run", "") for step in workflow["jobs"]["build"]["steps"]),
        )

        workflow_text = WORKFLOW.read_text(encoding="utf-8")
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                if not uses.startswith("actions/"):
                    continue
                owner, actual_sha = uses.split("@", 1)
                expected_sha, version = ACTION_PINS[owner]
                self.assertEqual(expected_sha, actual_sha)
                self.assertRegex(
                    workflow_text,
                    rf"uses:\s+{re.escape(owner)}@{expected_sha}\s+#\s+{re.escape(version)}",
                )

        build_text = json.dumps(workflow["jobs"]["build"])
        prerelease_text = json.dumps(workflow["jobs"]["prerelease"])
        release_text = json.dumps(workflow["jobs"]["release"])
        self.assertNotIn("contents: write", build_text)
        self.assertNotIn("OTA_SIGNING_PRIVATE_KEY", build_text)
        self.assertNotIn("OTA_SIGNING_PRIVATE_KEY", prerelease_text)
        self.assertIn("OTA_SIGNING_PRIVATE_KEY", release_text)
        self.assertIn("components/idf_web/OTA_RUNTIME_READY", build_text)
        self.assertNotIn("OTA_RUNTIME_READY", release_text.replace("ota_runtime_ready", ""))

        signer_script = named_step(workflow, "release", "Build signed OTA package")["run"]
        pinned = re.search(r"([0-9a-f]{64})  release-input/scripts/sign-ota-release.py", signer_script)
        self.assertIsNotNone(pinned, "release signer is not checksum-pinned")
        self.assertEqual(hashlib.sha256(SIGNER.read_bytes()).hexdigest(), pinned.group(1))

    def test_tag_gate_requires_exact_master_head_and_matching_semver(self):
        workflow = load_workflow()
        script = named_step(workflow, "build", "Verify release tag")["run"]
        self.assertIn('test "$GITHUB_REF_NAME" = "v$(', script)
        self.assertIn('"releaseVersion"', script)
        self.assertIn('test "$GITHUB_SHA" = "$(git rev-parse origin/master)"', script)
        self.assertNotIn("merge-base --is-ancestor", script)

    def test_branch_counter_gate_requires_valid_reachable_previous_metadata(self):
        current = '{"releaseVersion":"1.1.4","devBuild":15}\n'
        cases = (
            ("normal", '{"releaseVersion":"1.1.4","devBuild":14}\n', "previous", False, True),
            ("metadata-missing", None, "previous", False, False),
            ("metadata-malformed", '{"releaseVersion":"1.1.4","devBuild":true}\n', "previous", False, False),
            ("previous-ref-missing", '{"releaseVersion":"1.1.4","devBuild":14}\n', "missing", False, False),
            ("zero-before", '{"releaseVersion":"1.1.4","devBuild":14}\n', "zero", False, False),
            ("recreated-branch", '{"releaseVersion":"1.1.4","devBuild":14}\n', "zero", True, False),
        )
        for name, previous, before, recreate, expected in cases:
            with self.subTest(name=name):
                result = run_branch_counter_gate(
                    previous, current, before=before, recreate_branch=recreate
                )
                self.assertEqual(expected, result.returncode == 0, result.stderr)

    def test_branch_counter_gate_uses_pull_request_base_sha(self):
        result = run_branch_counter_gate(
            '{"releaseVersion":"1.1.4","devBuild":14}\n',
            '{"releaseVersion":"1.1.4","devBuild":15}\n',
            base_sha=True,
            base_ref="develop",
        )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_tag_gate_requires_a_new_counter_and_rejects_malformed_release_history(self):
        valid_previous = '{"releaseVersion":"1.1.3","devBuild":14}\n'
        current = '{"releaseVersion":"1.1.4","devBuild":15}\n'
        accepted = run_tag_gate(valid_previous, current)
        self.assertEqual(0, accepted.returncode, accepted.stderr)

        regressed = run_tag_gate(
            '{"releaseVersion":"1.1.3","devBuild":20}\n', current
        )
        self.assertNotEqual(0, regressed.returncode)

        malformed = run_tag_gate(
            '{"releaseVersion":"1.1.3","devBuild":true}\n', current
        )
        self.assertNotEqual(0, malformed.returncode)

    def test_existing_releases_fail_closed_and_new_releases_publish_exact_assets(self):
        workflow = load_workflow()
        scenarios = (
            (
                "prerelease",
                {"DEV_BUILD": "15", "RELEASE_VERSION": "1.1.4", "GITHUB_SHA": "abc"},
                ["dev-15", "sms-forwarder-dev-15.bin"],
            ),
            (
                "release",
                {
                    "GITHUB_REF_NAME": "v1.1.4",
                    "OTA_ASSET": "sms-forwarder-1.1.4.smsota",
                    "FULL_ASSET": "sms-forwarder-1.1.4.bin",
                },
                ["v1.1.4", "sms-forwarder-1.1.4.smsota", "sms-forwarder-1.1.4.bin"],
            ),
        )
        for job, env, expected in scenarios:
            script = named_step(workflow, job, "Publish GitHub prerelease" if job == "prerelease"
                                else "Publish GitHub release")["run"]
            with self.subTest(job=job), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                if job == "prerelease":
                    source = work / "release-input/dist/sms-forwarder-1.1.4.bin"
                    source.parent.mkdir(parents=True)
                    source.write_bytes(b"usb")
                existing = run_publish_script(script, work, release_exists=True, extra_env=env)
                self.assertNotEqual(0, existing.returncode)
                self.assertNotIn("release upload", (work / "gh.log").read_text(encoding="utf-8"))

            with self.subTest(job=f"{job}-new"), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                if job == "prerelease":
                    source = work / "release-input/dist/sms-forwarder-1.1.4.bin"
                    source.parent.mkdir(parents=True)
                    source.write_bytes(b"usb")
                created = run_publish_script(script, work, release_exists=False, extra_env=env)
                self.assertEqual(0, created.returncode, created.stderr)
                calls = (work / "gh.log").read_text(encoding="utf-8").splitlines()
                create = next(call for call in calls if call.startswith("release create "))
                for item in expected:
                    self.assertIn(item, create)
                command = shlex.split(create)
                first_option = next(
                    (index for index, item in enumerate(command[3:], start=3) if item.startswith("--")),
                    len(command),
                )
                published_assets = command[3:first_option]
                self.assertEqual(expected[1:], published_assets)


if __name__ == "__main__":
    unittest.main()
