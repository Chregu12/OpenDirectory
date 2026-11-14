#!/usr/bin/env python3
"""Read consistent Kubernetes database backups and verify them in disposable Docker PostgreSQL."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import traceback


RECEIVERS = {
    "identity": ["identity_company_role_receiving", "identity_company_group_rule_live_receiving", "identity_company_activation_receiving"],
    "devices": ["device_inventory_receiving", "device_compliance_receiving", "device_sync_receiving", "device_returns_receiving"],
    "app_store": [],
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def verify(args):
    os.umask(0o077)
    folder = Path(args.output_dir).expanduser().resolve()
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    kubectl = ["kubectl", "--context", args.context, "-n", args.namespace, "exec", "-i", args.pod, "--"]
    docker = ["docker", "--context", args.docker_context]
    container = "od-restore-check-" + secrets.token_hex(6)

    def source_sql(database):
        return kubectl + ["sh", "-c", 'exec psql -XqAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$1"', "sh", database]

    def run(command, **options):
        return subprocess.run(command, check=True, capture_output=True, **options).stdout

    def restore_sql(database, owner):
        return docker + ["exec", "-i", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", owner, "-d", database]

    report = {"checkedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source": {"context": args.context, "namespace": args.namespace, "pod": args.pod},
              "restore": {"dockerContext": args.docker_context, "image": args.restore_image}, "databases": {}}
    try:
        parameters = json.loads(run(source_sql(args.database[0]), input="SELECT json_build_object('owner',pg_get_userbyid(datdba),'backupUser',current_user,'version',current_setting('server_version')) FROM pg_database WHERE datname=current_database();", encoding="utf-8"))
        owner = parameters["owner"]
        report["source"]["version"] = parameters["version"]
        run(docker + ["run", "-d", "--name", container, "--label", "opendirectory.task=restore-rehearsal", "--network", "none", "--tmpfs", "/var/lib/postgresql/data",
                      "-e", "POSTGRES_USER=" + owner, "-e", "POSTGRES_PASSWORD=" + secrets.token_urlsafe(24), "-e", "POSTGRES_INITDB_ARGS=-c max_locks_per_transaction=256", args.restore_image])
        for _ in range(120):
            ready = subprocess.run(docker + ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", owner, "-d", "postgres"], capture_output=True)
            if ready.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Disposable PostgreSQL did not become ready")
        report["restore"]["version"] = run(restore_sql("postgres", owner), input="SHOW server_version;", encoding="utf-8").strip()
        report["restore"]["imageId"] = run(docker + ["inspect", container, "--format", "{{.Image}}"], encoding="utf-8").strip()
        for database in args.database:
            stderr_path = folder / (database + "-snapshot.stderr")
            with stderr_path.open("w", encoding="utf-8") as errors:
                client = subprocess.Popen(source_sql(database), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, encoding="utf-8")
                try:
                    client.stdin.write("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET timezone='UTC'; SELECT pg_export_snapshot();\n")
                    client.stdin.flush()
                    snapshot = client.stdout.readline().strip()
                    if not re.fullmatch(r"[0-9A-Fa-f-]{1,100}", snapshot):
                        raise RuntimeError("Source did not return an exported snapshot")
                    client.stdin.write("SELECT jsonb_build_object('owner',(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()),'tables',(SELECT jsonb_agg(tablename ORDER BY tablename COLLATE \"C\") FROM pg_tables WHERE schemaname='public'),'otherSchemas',COALESCE((SELECT jsonb_agg(DISTINCT schemaname) FROM pg_tables WHERE schemaname <> 'public' AND schemaname <> 'information_schema' AND schemaname !~ '^pg_'),'[]'::jsonb));\n")
                    client.stdin.flush()
                    inventory = json.loads(client.stdout.readline())
                    if inventory["owner"] != owner or inventory["otherSchemas"]:
                        raise RuntimeError("Select canonical public-schema databases with the same database owner")
                    tables = inventory["tables"]
                    if not tables or not all(re.fullmatch(r"[a-z_0-9]+", name) for name in tables):
                        raise RuntimeError("Expected explicit canonical public tables")
                    archive = folder / (database + ".dump")
                    partial = folder / (database + ".dump.partial")
                    with partial.open("wb") as output:
                        subprocess.run(kubectl + ["sh", "-c", 'exec pg_dump -U "$POSTGRES_USER" -d "$1" -Fc --snapshot "$2"', "sh", database, snapshot], stdout=output, stderr=errors, check=True)
                    partial.rename(archive)
                    parts = []
                    for table in tables:
                        parts.append("SELECT '" + table + "' AS name,count(*) AS count,encode(sha256(convert_to(COALESCE(string_agg(hash,'' ORDER BY hash COLLATE \"C\"),''),'UTF8')),'hex') AS sha256 FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS hash FROM public.\"" + table + '\" t) rows')
                    sql = 'SELECT jsonb_agg(to_jsonb(s) ORDER BY name COLLATE "C") FROM (' + " UNION ALL ".join(parts) + ") s;"
                    client.stdin.write(sql + "\n")
                    client.stdin.flush()
                    before = json.loads(client.stdout.readline())
                    client.stdin.write("COMMIT;\n")
                    client.stdin.close()
                    if client.wait(timeout=30) != 0:
                        raise RuntimeError("Source snapshot transaction failed")
                finally:
                    if client.poll() is None:
                        client.terminate()
                        try:
                            client.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            client.kill()
                            client.wait()
            run(docker + ["exec", container, "createdb", "-U", owner, database])
            with archive.open("rb") as source:
                run(docker + ["exec", "-i", container, "pg_restore", "-U", owner, "-d", database, "--exit-on-error"], stdin=source)
            actual = json.loads(run(restore_sql(database, owner), input="SET timezone='UTC';" + sql, encoding="utf-8"))
            expected = {row["name"]: row for row in before}
            if len(expected) != len(before) or len(actual) != len(expected) or {row["name"]: row for row in actual} != expected:
                raise RuntimeError(database + " restore does not match the exported source snapshot")
            checks = "BEGIN READ ONLY;" + "".join("SELECT " + name + "();" for name in RECEIVERS[database]) + "COMMIT;"
            run(restore_sql(database, owner), input=checks, encoding="utf-8")
            with archive.open("rb") as source:
                archive_hash = hashlib.file_digest(source, "sha256").hexdigest()
            result = {"archiveBytes": archive.stat().st_size, "archiveSha256": archive_hash,
                      "tables": len(tables), "sameRowCountsAndSha256ByTable": True, "transactionSnapshotSharedWithDump": True,
                      "ownershipAndPrivilegesRestoredFromArchive": True, "receiversPassed": RECEIVERS[database]}
            report["databases"][database] = result
            write_json(folder / (database + "-verification.json"), {"checks": result, "tables": before})
            print(json.dumps({database: result}), flush=True)
        report["status"] = "verified"
        report["completedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_json(folder / "verification.json", report)
        return report
    except BaseException as error:
        details = traceback.format_exc()
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            details += "\n" + (error.stderr.decode("utf-8", errors="replace") if isinstance(error.stderr, bytes) else error.stderr)
        (folder / "failure.log").write_text(details, encoding="utf-8")
        print("Restore verification failed. Private diagnostics: " + str(folder / "failure.log"), file=sys.stderr)
        raise
    finally:
        subprocess.run(docker + ["rm", "-f", container], capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, help="Explicit source kubectl context")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--pod", required=True, help="PostgreSQL pod with POSTGRES_USER configured")
    parser.add_argument("--database", choices=RECEIVERS, action="append", required=True)
    parser.add_argument("--docker-context", required=True, help="Explicit isolated restore Docker context")
    parser.add_argument("--output-dir", required=True, help="New private backup directory; must not exist")
    parser.add_argument("--restore-image", default="postgres:16")
    args = parser.parse_args()
    if sys.version_info < (3, 11) or os.name != "posix":
        parser.error("Python 3.11+ and POSIX private file permissions are required")
    if len(set(args.database)) != len(args.database):
        parser.error("Each database may be selected only once")
    for executable in ["kubectl", "docker"]:
        if not shutil.which(executable):
            parser.error(executable + " must be installed")
    try:
        verify(args)
    except FileExistsError:
        print("Choose a new output directory; existing backups are never overwritten.", file=sys.stderr)
        return 1
    except PermissionError:
        print("Cannot access the private output directory. Check its permissions.", file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
