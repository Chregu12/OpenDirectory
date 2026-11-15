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
    "auth": ["auth_employee_invitation_receiving"],
    "oauth": [],
}

# Expanded ACLs and PostgreSQL's pretty constraint deparser avoid equivalent dump/restore representations.
SCHEMA_SQL = """
SELECT jsonb_build_object(
 'routines',(SELECT jsonb_agg(jsonb_build_array(p.oid::regprocedure::text,pg_get_functiondef(p.oid),pg_get_userbyid(p.proowner),(SELECT jsonb_agg(jsonb_build_array(pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable) ORDER BY pg_get_userbyid(a.grantor) COLLATE "C",(CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END) COLLATE "C",a.privilege_type COLLATE "C") FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a)) ORDER BY p.oid::regprocedure::text COLLATE "C") FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind<>'a' AND NOT EXISTS(SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')),
 'triggers',(SELECT jsonb_agg(jsonb_build_array(c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) ORDER BY c.relname COLLATE "C",t.tgname COLLATE "C") FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(c.relname,k.conname,pg_get_constraintdef(k.oid,true)) ORDER BY c.relname COLLATE "C",k.conname COLLATE "C") FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(tablename,indexname,indexdef) ORDER BY tablename COLLATE "C",indexname COLLATE "C") FROM pg_indexes WHERE schemaname='public'),
 'columns',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname COLLATE "C",a.attnum) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='public' AND c.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped),
 'relations',(SELECT jsonb_agg(jsonb_build_array(c.relname,pg_get_userbyid(c.relowner),(SELECT jsonb_agg(jsonb_build_array(pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable) ORDER BY pg_get_userbyid(a.grantor) COLLATE "C",(CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END) COLLATE "C",a.privilege_type COLLATE "C") FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a),c.relrowsecurity,c.relforcerowsecurity) ORDER BY c.relname COLLATE "C") FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','p')),
 'policies',(SELECT jsonb_agg(jsonb_build_array(tablename,policyname,permissive,roles,cmd,qual,with_check) ORDER BY tablename COLLATE "C",policyname COLLATE "C") FROM pg_policies WHERE schemaname='public'),
 'extensions',(SELECT jsonb_agg(jsonb_build_array(extname,extversion) ORDER BY extname COLLATE "C") FROM pg_extension),
 'views',(SELECT jsonb_agg(jsonb_build_array(viewname,viewowner,definition) ORDER BY viewname COLLATE "C") FROM pg_views WHERE schemaname='public'),
 'sequences',(SELECT jsonb_agg(jsonb_build_array(sequencename,sequenceowner,data_type,start_value,min_value,max_value,increment_by,cycle,cache_size) ORDER BY sequencename COLLATE "C") FROM pg_sequences WHERE schemaname='public'));
"""


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


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
        # PostgreSQL deparsers can change equivalent SQL across major versions.
        report["restore"]["image"] = args.restore_image or "postgres:" + parameters["version"].split(".")[0]
        run(docker + ["run", "-d", "--name", container, "--label", "opendirectory.task=restore-rehearsal", "--network", "none", "--tmpfs", "/var/lib/postgresql/data",
                      "-e", "POSTGRES_USER=" + owner, "-e", "POSTGRES_PASSWORD=" + secrets.token_urlsafe(24), report["restore"]["image"], "postgres", "-c", "max_locks_per_transaction=256"])
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
                    client.stdin.write(SCHEMA_SQL + "\n")
                    client.stdin.flush()
                    schema_before = json.loads(client.stdout.readline())
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
            schema_actual = json.loads(run(restore_sql(database, owner), input=SCHEMA_SQL, encoding="utf-8"))
            write_json(folder / (database + "-schema.json"), {"source": schema_before, "restored": schema_actual})
            if schema_actual != schema_before:
                raise RuntimeError(database + " restored schema does not match the exported source snapshot")
            checks = "BEGIN READ ONLY;" + "".join("SELECT " + name + "();" for name in RECEIVERS[database]) + "COMMIT;"
            run(restore_sql(database, owner), input=checks, encoding="utf-8")
            with archive.open("rb") as source:
                archive_hash = hashlib.file_digest(source, "sha256").hexdigest()
            result = {"archiveBytes": archive.stat().st_size, "archiveSha256": archive_hash,
                      "tables": len(tables), "sameRowCountsAndSha256ByTable": True, "transactionSnapshotSharedWithDump": True,
                      "ownershipAndPrivilegesRestoredFromArchive": True, "receiversPassed": RECEIVERS[database]}
            result["schemaSha256"] = fingerprint(schema_before)
            result["sameCheckedSchemaDefinitions"] = True
            result["schemaCategories"] = sorted(schema_before)
            if database in args.upgrades:
                upgrade = args.upgrades[database]
                run(restore_sql(database, owner), input=upgrade["sql"], encoding="utf-8")
                after_upgrade = json.loads(run(restore_sql(database, owner), input="SET timezone='UTC';" + sql, encoding="utf-8"))
                if {row["name"]: row for row in after_upgrade} != expected:
                    raise RuntimeError(database + " candidate upgrade changed retained table data")
                run(restore_sql(database, owner), input=checks, encoding="utf-8")
                upgraded_schema = json.loads(run(restore_sql(database, owner), input=SCHEMA_SQL, encoding="utf-8"))
                write_json(folder / (database + "-upgraded-schema.json"), upgraded_schema)
                changed = sorted(key for key in schema_actual if schema_actual[key] != upgraded_schema[key])
                before_routines = {row[0]: row for row in schema_actual["routines"] or []}
                after_routines = {row[0]: row for row in upgraded_schema["routines"] or []}
                changed_routines = sorted(name for name in before_routines.keys() | after_routines.keys() if before_routines.get(name) != after_routines.get(name))
                result["candidateUpgrade"] = {"sqlSha256": upgrade["sha256"], "sameRetainedData": True, "schemaSha256": fingerprint(upgraded_schema), "changedSchemaCategories": changed, "changedRoutines": changed_routines}
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
    parser.add_argument("--restore-image", help="Disposable PostgreSQL image; defaults to the source major version")
    parser.add_argument("--verify-upgrade", action="append", default=[], metavar="DATABASE=SQL_FILE", help="Apply explicit candidate SQL only to its disposable restored database; retained data must stay identical")
    args = parser.parse_args()
    if sys.version_info < (3, 11) or os.name != "posix":
        parser.error("Python 3.11+ and POSIX private file permissions are required")
    if len(set(args.database)) != len(args.database):
        parser.error("Each database may be selected only once")
    args.upgrades = {}
    for value in args.verify_upgrade:
        database, separator, filename = value.partition("=")
        if not separator or database not in args.database or database in args.upgrades:
            parser.error("Upgrade SQL requires one explicitly selected database per DATABASE=SQL_FILE")
        path = Path(filename).expanduser()
        try:
            if not path.is_file() or path.stat().st_size > 1048576:
                raise ValueError()
            with path.open("rb") as source:
                data = source.read(1048577)
            if len(data) > 1048576: raise ValueError()
            sql = data.decode("utf-8")
            if not sql.strip(): raise ValueError()
        except (OSError, UnicodeError, ValueError):
            parser.error("Upgrade SQL must be a readable nonempty UTF-8 file, at most 1 MiB")
        args.upgrades[database] = {"sql": sql, "sha256": hashlib.sha256(data).hexdigest()}
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
