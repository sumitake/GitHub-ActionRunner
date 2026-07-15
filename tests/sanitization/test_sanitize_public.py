"""TDD suite for scripts/sanitize_public.py (the public-source sanitizer).

Written FIRST against the converged adversarial-reviewed spec (H1-H19) at
scratchpad/sanitizer-codegen-plan.md. Every H-item has at least one negative
test (a bypass-shaped fixture that MUST produce a finding) plus the two
mandated positive tests (canonical import prefix, canonical CODEOWNERS line).

Run: python3 -m unittest discover -s tests/sanitization -p 'test_*.py' -v
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import _sanitize_normalize as norm  # noqa: E402
import sanitize_public as sp  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def rules_of(findings):
    return {f.rule for f in findings}


def scan(text, relpath="notes.md", fixture=False):
    return sp.scan_text_content(text, relpath, fixture=fixture)


def line(text, relpath="notes.md", fixture=False, lineno=1):
    return sp.scan_line(lineno, text, relpath, fixture, os.path.basename(relpath))


def percent_encode_each_char(s: str) -> str:
    return "".join(f"%{ord(c):02X}" for c in s)


# ---------------------------------------------------------------------------
# Runtime secret-shape builders (Issue-2 fix).
#
# The scanner correctly never exempts secret rules by path, and it also
# reassembles adjacent quoted-string concatenation ("a" + "b" -> "ab"). So to
# keep THIS test file itself passing `--tracked`, secret-shaped inputs are
# assembled at runtime via _asm() (comma-separated fragments joined with
# str.join -- there is no "+" for the reassembler to collapse, and no single
# fragment contains a complete secret shape). No secret-shaped literal is ever
# committed; the shapes exist only in memory when the tests run.
# ---------------------------------------------------------------------------
def _asm(*parts: str) -> str:
    return "".join(parts)


def mk_ghp() -> str:
    return _asm("ghp", "_", "Z" * 24)


def mk_ssh_key() -> str:
    return _asm("ssh-", "ed25519 ", "AAAA", "C3Nz", "aC1lZDI1NTE5", "Ab" * 12)


def mk_age_key() -> str:
    return _asm("AGE-", "SECRET-", "KEY-1", "Q" * 40)


def mk_pem() -> str:
    return _asm("-----BEGIN ", "RSA ", "PRIVATE ", "KEY-----")


def mk_wireguard() -> str:
    return _asm("PrivateKey", " = ", "A" * 43, "=")


def mk_aws() -> str:
    return _asm("AKIA", "ABCDEFGHIJKLMNOP")


def mk_slack() -> str:
    return _asm("xox", "b-", "1234567890-", "abcdefghij")


def mk_stripe() -> str:
    return _asm("sk", "_live_", "ABCDEFGHIJ1234567890")


def mk_google() -> str:
    return _asm("AIza", "Sy", "A" * 35)


def mk_twilio() -> str:
    return _asm("SK", "a" * 32)


def mk_sendgrid() -> str:
    return _asm("SG.", "ABCDEFGHIJKLMNOPQRST", ".", "ABCDEFGHIJKLMNOPQRST")


def mk_npm() -> str:
    return _asm("npm", "_", "A" * 32)


def mk_pypi() -> str:
    return _asm("pypi", "-", "A" * 24)


def mk_assign(name_core: str, kind: str, value: str) -> str:
    # Build a labeled credential assignment without the label+value appearing
    # contiguously in this file's own source.
    return _asm(name_core, "_", kind, "=", value)


class PositiveTests(unittest.TestCase):
    """Canonical exceptions + synthetic fixtures MUST pass (no findings)."""

    def test_canonical_import_prefix_passes_bare(self):
        f = line("module github.com/sumitake/portable-ghar", "go.mod")
        self.assertNotIn("REPO_IDENTITY", rules_of(f))

    def test_canonical_import_prefix_passes_https(self):
        f = line("source: https://github.com/sumitake/portable-ghar.git", "docs/x.md")
        self.assertNotIn("REPO_IDENTITY", rules_of(f))

    def test_canonical_import_prefix_passes_ssh_clone(self):
        f = line("origin git@github.com:sumitake/portable-ghar.git", "CONTRIBUTING.md")
        self.assertNotIn("REPO_IDENTITY", rules_of(f))

    def test_canonical_import_prefix_passes_subpath(self):
        f = line("see https://github.com/sumitake/portable-ghar/tree/main/docs", "README.md")
        self.assertNotIn("REPO_IDENTITY", rules_of(f))

    def test_codeowners_exact_line_passes_in_codeowners_file(self):
        f = line("* @sumitake", "CODEOWNERS")
        self.assertNotIn("REPO_IDENTITY", rules_of(f))

    def test_synthetic_fixture_values_pass(self):
        text = (
            'Examples use owner/repository, example-fleet, and operator@example.invalid.\n'
            'Doc range: 203.0.113.7 is safe here.\n'
        )
        findings = scan(text, "docs/notes.md", fixture=True)
        self.assertEqual([], findings, findings)

    def test_synthetic_fixture_config_examples_path_passes(self):
        text = '"cidrs": ["192.168.0.0/16", "10.0.0.0/8"]\n'
        findings = scan(text, "config/examples/fleet.example.json", fixture=True)
        self.assertEqual([], findings, findings)


class H1PublicIP(unittest.TestCase):
    """H1: ALL IP literals are findings, not just the 8 private/special-use
    classes -- a real global-unicast WAN IP must not silently pass."""

    def test_public_wan_ipv4_is_a_finding(self):
        f = line("Public WAN address: 174.87.96.50 reachable", "notes.md")
        self.assertIn("IP001", rules_of(f))

    def test_public_ipv6_is_a_finding(self):
        f = line("edge range 2600:6c52:5100:2a42::1 observed", "notes.md")
        self.assertIn("IP001", rules_of(f))

    def test_fixture_path_exempts_ip(self):
        f = line("174.87.96.50", "docs/notes.md", fixture=True)
        self.assertNotIn("IP001", rules_of(f))


class H2FixtureQualification(unittest.TestCase):
    """H2: fixture-qualification is a CLOSED path allowlist, fail closed by
    default -- a doc-style IP on a non-fixture-path line is still a finding."""

    def test_doc_ip_on_non_fixture_path_is_a_finding(self):
        f = line("203.0.113.7 example", "NOTES.md", fixture=False)
        self.assertIn("IP001", rules_of(f))

    def test_same_content_passes_under_docs_prefix(self):
        findings = sp.scan_text_content("203.0.113.7 example\n", "docs/superpowers/x.md", fixture=sp.is_fixture_path("docs/superpowers/x.md"))
        self.assertEqual([], findings)

    def test_doc_deny_class_table_fixture_passes_under_docs_path_but_not_elsewhere(self):
        text = (FIXTURES_DIR / "deny_class_table.md").read_text()
        relpath_fixture = "docs/superpowers/specs/deny-classes.md"
        relpath_non_fixture = "NOTES.md"
        self.assertEqual([], sp.scan_text_content(text, relpath_fixture, fixture=sp.is_fixture_path(relpath_fixture)))
        findings = sp.scan_text_content(text, relpath_non_fixture, fixture=sp.is_fixture_path(relpath_non_fixture))
        self.assertIn("IP001", rules_of(findings))

    def test_is_fixture_path_closed_set(self):
        self.assertTrue(sp.is_fixture_path("tests/sanitization/fixtures/a.txt"))
        self.assertTrue(sp.is_fixture_path("config/examples/fleet.example.json"))
        self.assertTrue(sp.is_fixture_path("docs/superpowers/plans/x.md"))
        self.assertTrue(sp.is_fixture_path("worker/tests/fixtures/y.json"))
        self.assertFalse(sp.is_fixture_path("worker/src/protocol/version.ts"))
        self.assertFalse(sp.is_fixture_path("README.md"))


class H3Normalizer(unittest.TestCase):
    """H3: golden-vector IP normalization, shared/importable module, math
    subnet-membership via ipaddress (never string compare)."""

    def test_octal_dotted_quad(self):
        self.assertEqual(norm.parse_ipv4_literal("0177.0.0.1"), norm.ipaddress.IPv4Address("127.0.0.1"))

    def test_hex_dotted_quad(self):
        self.assertEqual(norm.parse_ipv4_literal("0x7f.0.0.1"), norm.ipaddress.IPv4Address("127.0.0.1"))

    def test_shorthand_two_part(self):
        self.assertEqual(norm.parse_ipv4_literal("127.1"), norm.ipaddress.IPv4Address("127.0.0.1"))

    def test_ipv4_mapped_ipv6_hexgroup_form(self):
        ip = norm.parse_ip_literal("::ffff:c0a8:0101")
        self.assertIsNotNone(ip)
        self.assertEqual(norm.classify_ip(ip), "privateUniqueLocal")  # 192.168.1.1

    def test_scoped_zone_percent_encoded(self):
        ip = norm.parse_ip_literal("fe80::1%25eth0")
        self.assertIsNotNone(ip)
        self.assertEqual(norm.classify_ip(ip), "linkLocalMetadata")

    def test_classify_ip_is_mathematical_not_string(self):
        # 192.168.1.1 written three different ways must classify identically.
        a = norm.classify_ip(norm.parse_ip_literal("192.168.1.1"))
        b = norm.classify_ip(norm.parse_ip_literal("0300.0250.01.01"))  # octal
        c = norm.classify_ip(norm.parse_ip_literal("::ffff:192.168.1.1"))
        self.assertEqual(a, b)
        self.assertEqual(a, c)
        self.assertEqual(a, "privateUniqueLocal")

    def test_scanner_detects_alt_forms_via_labeled_context(self):
        for text in ("loopback_alias: 0177.0.0.1", "loopback_alias: 0x7f.0.0.1", "loopback_alias: 127.1"):
            with self.subTest(text=text):
                f = line(text, "notes.md")
                self.assertIn("IP001", rules_of(f))

    def test_scanner_detects_ipv6_mapped_form(self):
        f = line("addr: ::ffff:c0a8:0101", "notes.md")
        self.assertIn("IP001", rules_of(f))

    def test_semver_is_not_misparsed_as_ip(self):
        # Regression guard for the false-positive collision discovered while
        # scoping H3: bare 2-/3-part shorthand parsing must stay context-gated.
        findings = scan('"version": "4.10.0"\n', "package.json")
        self.assertEqual([], findings, findings)


class H4Hostnames(unittest.TestCase):
    def test_single_label_device_name_labeled_context(self):
        f = line("hostname: RhoTor", "notes.md")
        self.assertIn("HOST001", rules_of(f))

    def test_dot_local_hostname(self):
        f = line("mDNS target: printer.local reachable", "notes.md")
        self.assertIn("HOST001", rules_of(f))

    def test_non_allowlisted_fqdn_labeled_context(self):
        f = line("hostname: rhohaus.johnosumi.example", "notes.md")
        self.assertIn("HOST001", rules_of(f))

    def test_punycode_label(self):
        f = line("hostname: xn--frs-hka.example", "notes.md")
        self.assertIn("HOST001", rules_of(f))

    def test_fixture_path_exempts_hostnames(self):
        f = line("hostname: RhoTor", "docs/notes.md", fixture=True)
        self.assertNotIn("HOST001", rules_of(f))


class H5UriAuthority(unittest.TestCase):
    def test_basic_auth_decoy_userinfo_flagged(self):
        f = line("source: https://example.invalid@real-host.example/path", "notes.md")
        self.assertIn("URI001", rules_of(f))

    def test_plain_url_without_userinfo_not_flagged_by_uri001(self):
        f = line("source: https://example.com/path", "notes.md")
        self.assertNotIn("URI001", rules_of(f))


class H6DeploymentIds(unittest.TestCase):
    def test_labeled_account_id(self):
        f = line("account_id=1234567890abcdef", "notes.md")
        self.assertIn("DEPLOYID001", rules_of(f))

    def test_bare_32_hex(self):
        f = line("token cache key abcdef0123456789abcdef0123456789 stored", "notes.md")
        self.assertIn("DEPLOYID002", rules_of(f))

    def test_bare_uuid(self):
        f = line("internal id 550e8400-e29b-41d4-a716-446655440000 assigned", "notes.md")
        self.assertIn("DEPLOYID002", rules_of(f))

    def test_git_sha_40_hex_not_misflagged_as_deployid002(self):
        # \b...{32}\b cannot match inside a uniform 40-hex run (no interior
        # word boundary) -- regression guard for the go.sum/git-SHA case.
        f = line("commit 6ce025902cd964747a078c2aabe7340ebc667eca", "notes.md")
        self.assertNotIn("DEPLOYID002", rules_of(f))

    def test_fixture_path_exempts_deployment_ids(self):
        f = line("account_id=1234567890abcdef", "docs/notes.md", fixture=True)
        self.assertNotIn("DEPLOYID001", rules_of(f))


class H7SecretCoverage(unittest.TestCase):
    def test_pem_block(self):
        f = line(mk_pem(), "notes.md")
        self.assertIn("SECRET_PEM", rules_of(f))

    def test_openssh_public_key_material(self):
        f = line(f"{mk_ssh_key()} user@host", "notes.md")
        self.assertIn("SECRET_SSHKEY", rules_of(f))

    def test_age_secret_key(self):
        f = line(mk_age_key(), "notes.md")
        self.assertIn("SECRET_SSHKEY", rules_of(f))

    def test_wireguard_private_key(self):
        f = line(mk_wireguard(), "notes.md")
        self.assertIn("SECRET_SSHKEY", rules_of(f))

    def test_full_github_prefix_table(self):
        for prefix in ("ghp", "gho", "ghs", "ghu", "ghr"):
            with self.subTest(prefix=prefix):
                tok = _asm(prefix, "_", "A" * 24)
                f = line(f"token: {tok}", "notes.md")
                self.assertIn("SECRET_TOKEN", rules_of(f))
        pat = _asm("github", "_pat_", "A" * 24)
        self.assertIn("SECRET_TOKEN", rules_of(line(f"token: {pat}", "notes.md")))

    def test_string_concat_reassembly(self):
        # Build the concat-shaped INPUT at runtime so the test file's own
        # source never contains a reassemble-able full token literal.
        concat_input = _asm("token = ", '"', "ghp", "_", '"', " + ", '"', "A" * 24, '"')
        f = line(concat_input, "notes.md")
        self.assertIn("SECRET_TOKEN", rules_of(f))

    def test_unicode_escaped_prefix(self):
        escaped = "".join(f"\\u{ord(c):04x}" for c in _asm("ghp", "_"))
        f = line(f"token: {escaped}{'A' * 24}", "notes.md")
        self.assertIn("SECRET_TOKEN", rules_of(f))

    def test_multiline_split_token(self):
        lines = [_asm("token_prefix ", "ghp", "_", "ABCDEFGHIJ"), "KLMNOPQRSTUVWXYZ0123 rest"]
        findings = sp._check_secrets_multiline(lines, "notes.md")
        self.assertIn("SECRET_TOKEN", {f.rule for f in findings})
        # and neither line alone triggers it (proves this is span-only coverage)
        self.assertNotIn("SECRET_TOKEN", rules_of(line(lines[0])))
        self.assertNotIn("SECRET_TOKEN", rules_of(line(lines[1])))

    def test_labeled_credential_assignment_with_entropy(self):
        f = line(mk_assign("API", "TOKEN", "zQ9k2LpN8xR4vT7mW1yB6cF3hJ0"), "notes.md")
        self.assertIn("SECRET_ASSIGN", rules_of(f))

    def test_labeled_credential_assignment_placeholder_not_flagged(self):
        f = line(mk_assign("API", "TOKEN", "changeme"), "notes.md")
        self.assertNotIn("SECRET_ASSIGN", rules_of(f))

    def test_secret_rules_apply_even_in_fixture_paths(self):
        f = line(mk_pem(), "docs/notes.md", fixture=True)
        self.assertIn("SECRET_PEM", rules_of(f))

    def test_runtime_generated_secrets_trip_every_shape(self):
        # Issue-2 fix: the multi-shape fixture is GENERATED in a tmpdir at test
        # time (never committed) so no secret-shaped file is ever tracked.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "synthetic_secrets.txt"
            p.write_text("\n".join([mk_pem(), mk_ssh_key(), f"token: {mk_ghp()}", mk_age_key()]) + "\n")
            text = p.read_text()
            found = rules_of(sp.scan_text_content(text, str(p), fixture=False))
        self.assertIn("SECRET_PEM", found)
        self.assertIn("SECRET_SSHKEY", found)
        self.assertIn("SECRET_TOKEN", found)


class H8PathGrammar(unittest.TestCase):
    def test_users_path(self):
        self.assertIn("PATH001", rules_of(line("backup at /Users/jsmith/secret.txt", "notes.md")))

    def test_home_path(self):
        self.assertIn("PATH001", rules_of(line("key at /home/alice/.ssh/id_rsa", "notes.md")))

    def test_root_ssh_path(self):
        self.assertIn("PATH001", rules_of(line("see /root/.ssh/config", "notes.md")))

    def test_windows_profile_path(self):
        self.assertIn("PATH001", rules_of(line(r"C:\Users\alice\file.txt", "notes.md")))

    def test_unc_path(self):
        self.assertIn("PATH001", rules_of(line(r"\\fileserver\share\doc.txt", "notes.md")))

    def test_file_uri(self):
        self.assertIn("PATH001", rules_of(line("file:///etc/passwd", "notes.md")))

    def test_nas_share_path(self):
        self.assertIn("PATH001", rules_of(line("/share/CACHEDEV1_DATA/foo", "notes.md")))

    def test_home_env_var(self):
        self.assertIn("PATH001", rules_of(line("cd $HOME/project", "notes.md")))

    def test_fixture_path_exempts_paths(self):
        self.assertNotIn("PATH001", rules_of(line("/Users/jsmith/secret.txt", "docs/notes.md", fixture=True)))


class H9ArchiveScope(unittest.TestCase):
    def _zip_bytes(self, members: dict) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return buf.getvalue()

    def test_zip_member_secret_detected(self):
        raw = self._zip_bytes({"inner.txt": "token: ghp_" + "A" * 24})
        findings = sp.scan_bytes_as_file(raw, "bundle.whl", fixture=False)
        self.assertIn("SECRET_TOKEN", {f.rule for f in findings})

    def test_office_zip_family_by_magic_not_extension(self):
        raw = self._zip_bytes({"word/document.xml": "token: ghp_" + "B" * 24})
        findings = sp.scan_bytes_as_file(raw, "report.docx", fixture=False)
        self.assertIn("SECRET_TOKEN", {f.rule for f in findings})

    @staticmethod
    def _force_encrypted_flag(raw: bytes) -> bytes:
        # zipfile cannot WRITE an actually-encrypted member (read-only
        # decryption support), so binary-patch the general-purpose bit flag
        # (bit 0 = encrypted) in both the local file header and the central
        # directory record -- this is the same structural signal the
        # scanner's `info.flag_bits & 0x1` check reads on a real password-
        # protected zip member.
        import struct

        patched = bytearray(raw)
        local_off = patched.find(b"PK\x03\x04")
        struct.pack_into("<H", patched, local_off + 6, struct.unpack_from("<H", patched, local_off + 6)[0] | 0x1)
        central_off = patched.find(b"PK\x01\x02")
        struct.pack_into("<H", patched, central_off + 8, struct.unpack_from("<H", patched, central_off + 8)[0] | 0x1)
        return bytes(patched)

    def test_zip_encrypted_member_is_finding(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("secret.bin", b"irrelevant")
        raw = self._force_encrypted_flag(buf.getvalue())
        findings = sp.scan_bytes_as_file(raw, "bundle.zip", fixture=False)
        self.assertIn("ARCHIVE_ENCRYPTED", {f.rule for f in findings})

    def test_zip_symlink_member_is_finding(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("link")
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "/etc/passwd")
        findings = sp.scan_bytes_as_file(buf.getvalue(), "bundle.zip", fixture=False)
        self.assertIn("ARCHIVE_SYMLINK", {f.rule for f in findings})

    def test_tar_symlink_member_is_finding(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo(name="link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
        findings = sp.scan_bytes_as_file(buf.getvalue(), "bundle.tar", fixture=False)
        self.assertIn("ARCHIVE_SYMLINK", {f.rule for f in findings})

    def test_gzip_single_stream_secret_detected(self):
        raw = gzip.compress(("token: ghp_" + "C" * 24).encode("utf-8"))
        findings = sp.scan_bytes_as_file(raw, "payload.txt.gz", fixture=False)
        self.assertIn("SECRET_TOKEN", {f.rule for f in findings})

    def test_unsupported_zstd_magic_is_finding(self):
        raw = b"\x28\xb5\x2f\xfd" + b"\x00" * 20
        findings = sp.scan_bytes_as_file(raw, "payload.zst", fixture=False)
        self.assertIn("ARCHIVE_UNSUPPORTED", {f.rule for f in findings})

    def test_depth_cap_enforced(self):
        findings = sp.scan_bytes_as_file(b"anything", "deep.bin", fixture=False, depth=sp.ARCHIVE_MAX_DEPTH + 1)
        self.assertIn("ARCHIVE_DEPTH", {f.rule for f in findings})


class H10History(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        run = lambda *args: subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        run("init", "-q", "-b", "main")
        run("config", "user.email", "test@example.com")
        run("config", "user.name", "Test")
        (self.repo / "secret.txt").write_text("internal_id 550e8400-e29b-41d4-a716-446655440000\n")
        run("add", "secret.txt")
        run("commit", "-q", "-m", f"add secret {mk_ghp()} for CI")
        (self.repo / "secret.txt").unlink()
        run("commit", "-q", "-am", "remove secret file")

    def tearDown(self):
        self.tmp.cleanup()

    def test_deleted_blob_still_reachable_and_scanned(self):
        findings = sp.scan_history(self.repo)
        paths = {f.path for f in findings}
        self.assertTrue(any("secret.txt@" in p for p in paths), paths)

    def test_commit_message_identifier_caught(self):
        findings = sp.scan_history(self.repo)
        self.assertTrue(any(f.rule == "HISTORY_META" and "subject" in f.path for f in findings), findings)


class H11GeneratedManifest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        (self.repo / "dist").mkdir()
        (self.repo / "dist" / "out.js").write_text("console.log(1)\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_generated_flag_is_a_finding(self):
        findings = sp.check_generated_manifest(self.repo, [])
        self.assertIn("GENERATED_MISSING", {f.rule for f in findings})

    def test_passing_generated_flag_suppresses_it(self):
        findings = sp.check_generated_manifest(self.repo, ["dist"])
        self.assertNotIn("GENERATED_MISSING", {f.rule for f in findings})


class H12DecodeChainAndResidual(unittest.TestCase):
    def test_entity_percent_base64_chain_to_secret(self):
        secret = mk_ghp()
        b64 = base64.b64encode(secret.encode()).decode()
        percent = "".join(f"%{ord(c):02X}" for c in b64)
        entity = "".join(f"&#{ord(c)};" for c in percent)
        f = line(f"blob: {entity}", "notes.md")
        self.assertIn("SECRET_TOKEN", rules_of(f))

    def test_data_uri_embedded_secret(self):
        secret = mk_ghp()
        b64 = base64.b64encode(secret.encode()).decode()
        f = line(f"see data:text/plain;base64,{b64} for details", "notes.md")
        self.assertIn("SECRET_TOKEN", rules_of(f))

    def test_base64_secret_embedded_in_text(self):
        # base64 of TEXT CONTAINING a token (embedded, not a standalone blob)
        plaintext = f"config token={mk_ghp()} enabled=true"
        payload = base64.b64encode(plaintext.encode()).decode()
        f = line(f"opaque: {payload}", "notes.md")
        self.assertIn("SECRET_TOKEN", rules_of(f))

    def test_base64_ip_embedded_in_text(self):
        # base64 of TEXT CONTAINING an IP (embedded, not a standalone IP)
        plaintext = "resolved host 174.87.96.50 during boot"
        payload = base64.b64encode(plaintext.encode()).decode()
        f = line(f"opaque: {payload}", "notes.md")
        self.assertIn("IP001", rules_of(f))

    def test_hex_ip_embedded_in_text(self):
        plaintext = "peer 192.168.1.1 down"
        payload = plaintext.encode().hex()
        f = line(f"opaque: {payload}", "notes.md")
        self.assertIn("IP001", rules_of(f))

    def test_fullwidth_path_separator(self):
        # fullwidth solidus (U+FF0F) built via chr() so this source file holds
        # no literal fullwidth separator glyph.
        fw = chr(0xFF0F)
        f = line(f"path: C{fw}Users{fw}name", "notes.md")
        self.assertIn("ENCODED_RESIDUAL", rules_of(f))

    def test_residual_fail_closed_after_budget(self):
        hextoken = "0123456789abcdef" * 2  # 32 hex chars, clean alphabet
        layer1 = percent_encode_each_char(hextoken)
        layer2 = percent_encode_each_char(layer1)
        layer3 = percent_encode_each_char(layer2)
        f = line(f"blob: {layer3}", "notes.md")
        self.assertIn("ENCODED_RESIDUAL", rules_of(f))

    def test_looks_still_encoded_unit(self):
        self.assertTrue(norm.looks_still_encoded("a" * 40))
        self.assertFalse(norm.looks_still_encoded("hello world"))


class H13CanonicalExceptionTable(unittest.TestCase):
    def test_near_miss_repo_suffix_hijack(self):
        f = line("clone https://github.com/sumitake/portable-ghar-private-keys", "notes.md")
        self.assertIn("REPO_IDENTITY", rules_of(f))

    def test_near_miss_owner_bot_suffix(self):
        f = line("reviewed by @sumitake-bot", "notes.md")
        self.assertIn("REPO_IDENTITY", rules_of(f))

    def test_near_miss_wrong_owner(self):
        f = line("fork at github.com/not-sumitake/portable-ghar", "notes.md")
        self.assertIn("REPO_IDENTITY", rules_of(f))

    def test_codeowners_line_outside_codeowners_file_is_finding(self):
        f = line("* @sumitake", "docs/governance.md")
        self.assertIn("REPO_IDENTITY", rules_of(f))

    def test_unrelated_third_party_repo_not_flagged(self):
        f = line("uses github.com/actions/scaleset and github.com/google/nftables", "go.mod")
        self.assertNotIn("REPO_IDENTITY", rules_of(f))

    def test_own_package_name_not_flagged(self):
        f = line('"name": "@portable-ghar/worker"', "worker/package.json")
        self.assertNotIn("REPO_IDENTITY", rules_of(f))


class H14AllowlistModel(unittest.TestCase):
    def test_line_scope_suppresses_exact_match(self):
        text = "hostname: RhoTor\n"
        findings = scan(text, "notes.md")
        self.assertTrue(findings)
        f = findings[0]
        h = sp.compute_line_hash(f.content)
        allow = sp.AllowlistIndex(
            [{"path": "notes.md", "line": 1, "rule": f.rule, "sha256": h, "reason": "test"}]
        )
        self.assertEqual([], allow.filter(findings))

    def test_changed_line_content_is_not_suppressed(self):
        findings = scan("hostname: RhoTor\n", "notes.md")
        f = findings[0]
        stale_hash = "0" * 64
        allow = sp.AllowlistIndex([{"path": "notes.md", "line": 1, "rule": f.rule, "sha256": stale_hash, "reason": "stale"}])
        self.assertEqual(findings, allow.filter(findings))

    def test_whole_file_binary_allowlist(self):
        raw = b"\x89PNG\r\n\x1a\n" + os.urandom(64)
        h = sp.compute_file_hash(raw)
        findings = sp.scan_bytes_as_file(raw, "logo.png", fixture=False)
        self.assertTrue(any(f.rule == "BINARY_UNALLOWLISTED" for f in findings))
        allow = sp.AllowlistIndex([{"path": "logo.png", "line": "file", "rule": "BINARY_UNALLOWLISTED", "sha256": h, "reason": "icon"}])
        self.assertEqual([], allow.filter(findings))

    def test_multiline_span_allowlist(self):
        lines = ["token_prefix ghp_ABCDEFGHIJ", "KLMNOPQRSTUVWXYZ0123 rest"]
        findings = sp._check_secrets_multiline(lines, "notes.md")
        f = findings[0]
        h = sp.compute_span_hash(lines)
        allow = sp.AllowlistIndex([{"path": "notes.md", "line": f.line, "rule": f.rule, "sha256": h, "reason": "synthetic test token"}])
        self.assertEqual([], allow.filter(findings))

    def test_trailing_space_canonicalizes_to_same_hash(self):
        h_lf = sp.compute_line_hash("hello world")
        h_trailing_space = sp.compute_line_hash("hello world  \t")
        self.assertEqual(h_lf, h_trailing_space)

    def test_crlf_split_file_yields_same_line_text_as_lf(self):
        # The canonicalization that matters in practice happens at the
        # whole-file split (scan_text_content uses re.split on \r\n|\r|\n),
        # so a CRLF-ending file and an LF-ending file with identical content
        # produce identical per-line finding content/hashes.
        crlf_findings = scan("hostname: RhoTor\r\n", "notes.md")
        lf_findings = scan("hostname: RhoTor\n", "notes.md")
        self.assertEqual(
            sp.compute_line_hash(crlf_findings[0].content),
            sp.compute_line_hash(lf_findings[0].content),
        )

    def test_wildcard_path_rejected(self):
        p = self._write_allowlist([{"path": "docs/*", "line": 1, "rule": "IP001", "sha256": "0" * 64, "reason": "x"}])
        with self.assertRaises(sp.AllowlistError):
            sp.load_allowlist(p)

    def test_unknown_rule_rejected(self):
        p = self._write_allowlist([{"path": "a.md", "line": 1, "rule": "NOT_A_RULE", "sha256": "0" * 64, "reason": "x"}])
        with self.assertRaises(sp.AllowlistError):
            sp.load_allowlist(p)

    def test_duplicate_entry_rejected(self):
        entry = {"path": "a.md", "line": 1, "rule": "IP001", "sha256": "0" * 64, "reason": "x"}
        p = self._write_allowlist([entry, dict(entry)])
        with self.assertRaises(sp.AllowlistError):
            sp.load_allowlist(p)

    def _write_allowlist(self, entries):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(entries, tmp)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return Path(tmp.name)


class H15SymlinkSubmodule(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        run = lambda *args: subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        run("init", "-q", "-b", "main")
        run("config", "user.email", "test@example.com")
        run("config", "user.name", "Test")

    def tearDown(self):
        self.tmp.cleanup()

    def test_tracked_symlink_is_finding(self):
        run = lambda *args: subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        (self.repo / "target.txt").write_text("hello\n")
        os.symlink("target.txt", self.repo / "link.txt")
        run("add", "-A")
        run("commit", "-q", "-m", "add symlink")
        findings = sp.scan_tracked(self.repo)
        self.assertIn("SYMLINK_TRACKED", {f.rule for f in findings})

    def test_gitmodules_present_is_finding(self):
        (self.repo / ".gitmodules").write_text('[submodule "vendor"]\n\tpath = vendor\n\turl = https://github.com/example/vendor.git\n')
        run = lambda *args: subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)
        run("add", "-A")
        run("commit", "-q", "-m", "add submodule config")
        findings = sp.scan_tracked(self.repo)
        self.assertIn("SUBMODULE_PRESENT", {f.rule for f in findings})


class H16PersonalIdentity(unittest.TestCase):
    def test_ssh_key_comment_structural(self):
        f = line(f"{mk_ssh_key()} claude@RhoTor", "notes.md")
        self.assertIn("SECRET_SSHKEY", rules_of(f))

    def test_private_denylist_catches_free_text_pii(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "notes.md").write_text("Contact John Osumi about the RhoNAS migration.\n")
            deny = repo / "deny.txt"
            deny.write_text("John Osumi\nRhoNAS\n")
            findings = sp.scan_private_denylist(repo, tracked=False, generated=[str(repo / "notes.md")], denylist_path=deny, history=False)
            self.assertIn("PRIVATE_DENYLIST", {f.rule for f in findings})

    def test_private_denylist_never_echoes_terms_in_output(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "notes.md").write_text("Contact John Osumi about the RhoNAS migration.\n")
            deny = repo / "deny.txt"
            deny.write_text("John Osumi\n")
            findings = sp.scan_private_denylist(repo, tracked=False, generated=[str(repo / "notes.md")], denylist_path=deny, history=False)
            for f in findings:
                self.assertNotIn("deny.txt", sp.format_finding(f))


class H17GitLfs(unittest.TestCase):
    def test_gitattributes_lfs_filter_is_finding(self):
        findings = scan("*.bin filter=lfs diff=lfs merge=lfs -text\n", ".gitattributes")
        self.assertIn("LFS_TRACKED", rules_of(findings))

    def test_lfs_pointer_stub_is_finding(self):
        # Built at runtime (not committed) -- a tracked LFS-pointer fixture
        # would itself trip LFS_TRACKED under --tracked.
        pointer = _asm("version https://git-lfs.github.com/spec/v1", "\n", "oid sha256:", "a" * 64, "\nsize 12345\n")
        findings = scan(pointer, "model.bin")
        self.assertIn("LFS_TRACKED", rules_of(findings))


class H18VendorTokens(unittest.TestCase):
    def test_aws_access_key(self):
        self.assertIn("SECRET_TOKEN", rules_of(line(f"key: {mk_aws()}", "notes.md")))

    def test_slack_token(self):
        self.assertIn("SECRET_TOKEN", rules_of(line(f"token: {mk_slack()}", "notes.md")))

    def test_stripe_live_key(self):
        self.assertIn("SECRET_TOKEN", rules_of(line(f"key: {mk_stripe()}", "notes.md")))

    def test_google_api_key(self):
        self.assertIn("SECRET_TOKEN", rules_of(line(f"key: {mk_google()}", "notes.md")))

    def test_twilio_key(self):
        self.assertIn("SECRET_TOKEN", rules_of(line(f"sid: {mk_twilio()}", "notes.md")))

    def test_sendgrid_key(self):
        self.assertIn("SECRET_TOKEN", rules_of(line(f"key: {mk_sendgrid()}", "notes.md")))

    def test_npm_token(self):
        self.assertIn("SECRET_TOKEN", rules_of(line(f"token: {mk_npm()}", "notes.md")))

    def test_pypi_token(self):
        self.assertIn("SECRET_TOKEN", rules_of(line(f"token: {mk_pypi()}", "notes.md")))

    def test_labeled_fallback_independent_of_entropy_prefix_still_flagged(self):
        self.assertIn("SECRET_ASSIGN", rules_of(line(mk_assign("DEPLOY", "SECRET", "abcdefgh12345678"), "notes.md")))


class H19DecodeLayers(unittest.TestCase):
    def test_hex_layer_decode(self):
        secret = mk_ghp()
        hexed = secret.encode().hex()
        layers, still_encoded = norm.decode_residual_layers(hexed)
        self.assertIn(secret, layers)

    def test_base32_layer_decode(self):
        secret = mk_ghp()
        b32 = base64.b32encode(secret.encode()).decode()
        layers, still_encoded = norm.decode_residual_layers(b32)
        self.assertIn(secret, layers)

    def test_base64url_layer_decode(self):
        secret = mk_ghp()
        b64u = base64.urlsafe_b64encode(secret.encode()).decode()
        layers, still_encoded = norm.decode_residual_layers(b64u)
        self.assertIn(secret, layers)

    def test_base32_secret_embedded_in_text_flagged_by_scanner(self):
        plaintext = f"credential {mk_ghp()} rotated"
        payload = base64.b32encode(plaintext.encode()).decode()
        f = line(f"opaque: {payload}", "notes.md")
        self.assertIn("SECRET_TOKEN", rules_of(f))

    def test_base64url_ip_embedded_in_text_flagged_by_scanner(self):
        plaintext = "endpoint 192.168.1.1 blocked"
        payload = base64.urlsafe_b64encode(plaintext.encode()).decode().rstrip("=")
        f = line(f"opaque: {payload}", "notes.md")
        self.assertIn("IP001", rules_of(f))

    def test_hex_secret_embedded_in_text_flagged_by_scanner(self):
        plaintext = f"api key {mk_ghp()} here"
        payload = plaintext.encode().hex()
        f = line(f"opaque: {payload}", "notes.md")
        self.assertIn("SECRET_TOKEN", rules_of(f))

    def test_residual_hex_fail_closed(self):
        self.assertTrue(norm.looks_still_encoded("deadbeef" * 5))


class CliAndIntegration(unittest.TestCase):
    def test_diagnostic_line_format(self):
        f = sp.Finding("a.md", 3, "IP001", "example message", "")
        self.assertEqual(sp.format_finding(f), "a.md:3:IP001: example message")

    def test_allowlist_invalid_json_causes_exit_1_via_cli(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            (repo / ".sanitization-allowlist.json").write_text('[{"path": "a", "line": "*", "rule": "IP001", "sha256": "0", "reason": "x"}]')
            result = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "sanitize_public.py"), "--tracked"],
                cwd=repo,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("ALLOWLIST_INVALID", result.stdout)

    def test_clean_tracked_run_against_real_repo(self):
        """Step 5 of the TDD sequence: run --tracked against the CURRENT
        repository working tree and require a clean pass."""
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "sanitize_public.py"), "--tracked"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("sanitization passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
