"""CLI safety checks and optional isolated PostgreSQL schema regression checks."""

import importlib.util
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name("verify-postgres-restore.py")


class RestoreCliSafety(unittest.TestCase):
    def test_invalid_or_existing_destinations_never_call_external_tools(self):
        with tempfile.TemporaryDirectory(prefix="od-restore-cli-") as temporary:
            root = Path(temporary)
            called = root / "external-tool-called"
            for name in ["kubectl", "docker"]:
                path = root / name
                path.write_text("#!/bin/sh\nprintf called > " + shlex.quote(str(called)) + "\nexit 71\n")
                path.chmod(0o700)
            environment = {**os.environ, "PATH": str(root)}
            output = root / "new-backup"
            valid = root / "candidate.sql"
            valid.write_text("SELECT 1;\n")
            empty = root / "empty.sql"
            empty.touch()
            invalid = root / "invalid.sql"
            invalid.write_bytes(b"\xff")
            large = root / "large.sql"
            large.write_bytes(b"x" * 1048577)
            base = ["--context", "must-not-contact", "--namespace", "test", "--pod", "test", "--docker-context", "must-not-contact", "--output-dir", str(output)]
            cases = [
                [],
                base + ["--database", "auth", "--database", "auth"],
                base + ["--database", "oauth", "--verify-upgrade", "auth=" + str(valid)],
                base + ["--database", "oauth", "--verify-upgrade", "oauth=" + str(valid), "--verify-upgrade", "oauth=" + str(valid)],
                base + ["--database", "oauth", "--verify-upgrade", "oauth=" + str(root / "missing.sql")],
                base + ["--database", "oauth", "--verify-upgrade", "oauth=" + str(empty)],
                base + ["--database", "oauth", "--verify-upgrade", "oauth=" + str(invalid)],
                base + ["--database", "oauth", "--verify-upgrade", "oauth=" + str(large)],
                base + ["--database", "oauth", "--verify-upgrade", "oauth=" + str(root)],
            ]
            for args in cases:
                with self.subTest(args=args):
                    result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, env=environment)
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(output.exists())
                    self.assertFalse(called.exists())
            output.mkdir()
            retained = output / "retained.txt"
            retained.write_text("Personal data must stay intact.")
            result = subprocess.run([sys.executable, str(SCRIPT), *base, "--database", "auth", "--database", "oauth"], capture_output=True, env=environment)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(retained.read_text(), "Personal data must stay intact.")
            self.assertFalse(called.exists())


class RestoreSchemaComparison(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("RESTORE_TEST_DOCKER_CONTEXT"), "Set an explicit disposable Docker context to test PostgreSQL schema comparisons")
    def test_equivalent_acls_and_constraints_still_detect_real_changes(self):
        spec = importlib.util.spec_from_file_location("restore_verifier", SCRIPT)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        docker = ["docker", "--context", os.environ["RESTORE_TEST_DOCKER_CONTEXT"]]
        container = "od-restore-schema-test-" + secrets.token_hex(6)

        def run(args, **options):
            return subprocess.run(docker + args, check=True, capture_output=True, text=True, timeout=120, **options).stdout

        def sql(statement):
            return run(["exec", "-i", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "proof", "-d", "proof"], input=statement)

        def schema():
            return json.loads(sql(verifier.SCHEMA_SQL))

        try:
            run(["run", "-d", "--name", container, "--label", "opendirectory.task=restore-schema-test", "--network", "none", "--tmpfs", "/var/lib/postgresql/data", "-e", "POSTGRES_USER=proof", "-e", "POSTGRES_PASSWORD=" + secrets.token_urlsafe(24), "postgres:15-alpine"])
            for _ in range(120):
                ready = subprocess.run(docker + ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "proof"], capture_output=True)
                if ready.returncode == 0:
                    break
                time.sleep(0.25)
            else:
                self.fail("Disposable PostgreSQL did not become ready")
            sql("CREATE TABLE proof(value int CHECK ((value>=1 AND value<=10) AND value<>5)); CREATE FUNCTION proof() RETURNS int LANGUAGE sql AS 'SELECT 1';")
            original = schema()
            sql("GRANT ALL ON TABLE proof TO proof; ALTER TABLE proof DROP CONSTRAINT proof_value_check; ALTER TABLE proof ADD CONSTRAINT proof_value_check CHECK (value>=1 AND value<=10 AND value<>5);")
            self.assertEqual(schema(), original)
            sql("GRANT SELECT ON TABLE proof TO PUBLIC;")
            self.assertNotEqual(schema()["relations"], original["relations"])
            sql("REVOKE SELECT ON TABLE proof FROM PUBLIC;")
            self.assertEqual(schema(), original)
            sql("ALTER TABLE proof DROP CONSTRAINT proof_value_check; ALTER TABLE proof ADD CONSTRAINT proof_value_check CHECK (value>=1 AND value<=10 AND value<>6);")
            self.assertNotEqual(schema()["constraints"], original["constraints"])
            sql("REVOKE EXECUTE ON FUNCTION proof() FROM PUBLIC;")
            self.assertNotEqual(schema()["routines"], original["routines"])
        finally:
            subprocess.run(docker + ["rm", "-f", container], capture_output=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
