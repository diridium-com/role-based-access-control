# SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
# SPDX-License-Identifier: MPL-2.0

"""The scenarios. Each one gets its own new database and a freshly unpacked engine.

A check that fails is a FAIL and fails the run. A NOTE records something without judging it.
"""

import hashlib
import os
import re
import xml.etree.ElementTree as ET
import zipfile

import checks as k
import rbac as b
from oie import Api

PASSWORD = "Rbac-e2e-" + b.new_id()[:12] + "!"
# rbac writes these at WARN on purpose: every refusal, and the blocked deletion of the last admin user.
EXPECTED_WARN = (r"RBAC: User \d+ denied for operation", r"RBAC: blocked deletion of the last admin user")


class Report:
    def __init__(self, scenario):
        self.scenario = scenario
        self.passed = 0
        self.failed = []
        self.notes = []

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
        else:
            self.failed.append(name)
        print(f"{'PASS' if ok else 'FAIL'} [{self.scenario}] {name}" + (f"  [{detail}]" if detail and not ok else ""),
              flush=True)
        return ok

    def note(self, name, value):
        self.notes.append(f"{name}: {value}")
        print(f"NOTE [{self.scenario}] {name}: {value}", flush=True)

    def known(self, name, ok, issue, detail=""):
        """A check that fails today because of an open issue: failing is a NOTE, not a FAIL. Passing is a PASS plus
        a NOTE that the issue looks fixed and its marker can go."""
        if ok:
            self.check(name, True)
            self.note("known failure passes", f"{name}: {issue} looks fixed; remove its marker in e2e/")
        else:
            self.note("known failure", f"{name} ({issue})" + (f" [{detail}]" if detail else ""))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def zip_versions(zip_path):
    """(pluginVersion, mirthVersion) from the zip's plugin.xml."""
    with zipfile.ZipFile(zip_path) as z:
        root = ET.fromstring(z.read("rbac/plugin.xml"))
    return root.findtext("pluginVersion"), root.findtext("mirthVersion")


def check_server_jar(r, engine, zip_path):
    """The installed server jar must be the zip's, and the only one (an upgrade must not leave the old one)."""
    with zipfile.ZipFile(zip_path) as z:
        name = next(n for n in z.namelist() if re.search(r"rbac-server-[^/]*\.jar$", n))
        want = sha256(z.read(name))
    files = engine.extension_files(b.PLUGIN_PATH) or []
    jars = [f for f in files if f.startswith("rbac-server-")]
    got = None
    if len(jars) == 1:
        with open(os.path.join(engine.home, "extensions", b.PLUGIN_PATH, jars[0]), "rb") as f:
            got = sha256(f.read())
    r.check(f"installed server jar is {os.path.basename(name)} and the only one",
            jars == [os.path.basename(name)] and got == want, f"found {jars}")


def install_and_restart(r, engine, api, zip_path, check_loaded=True):
    ok, detail = b.install(api, zip_path)
    r.check(f"install {os.path.basename(zip_path)}", ok, detail)
    api = engine.restart()
    check_server_jar(r, engine, zip_path)
    if check_loaded:
        check_plugin_loaded(r, api, zip_path)
    return api


def check_plugin_loaded(r, api, zip_path):
    meta = b.plugin_meta(api)
    r.check(f"the engine loaded rbac {'/'.join(zip_versions(zip_path))} (version/engine)", meta == zip_versions(zip_path),
            str(meta))


def check_logs(r, engine, allowed=(), where=""):
    """allowed: regular expressions for ERROR and WARN lines this scenario causes on purpose."""
    for level in ("ERROR", "WARN"):
        lines = [line for line in engine.plugin_log_lines(level)
                 if not any(re.search(p, line) for p in (*EXPECTED_WARN, *allowed))]
        r.check(f"no unexpected {level} lines from rbac in mirth.log{where}", not lines, " | ".join(lines[:3]))


def login(engine, name):
    session = Api(engine.port, name, PASSWORD)
    session.login(wait=60)
    return session


def check_tables(r, db, dbname, want, where=""):
    tables = db.plugin_table_count(dbname)
    if tables is not None:
        r.check(f"{where}{want} of rbac's four tables exist", tables == want, f"found {tables}")


def check_schema_version(r, db, dbname, where=""):
    version = db.schema_version(dbname)
    if version is not None or db.kind != "derby":
        r.check(f"{where}schema_version is 3 in CONFIGURATION", version == 3, f"found {version}")


# ---------- fresh install: every feature

def fresh(r, engine, db, dbname, new_zip, **_):
    api = engine.start()
    early = {key: b.create_user(api, "rbac-e2e-" + key, PASSWORD) for key in ("early-1", "early-2")}
    api = install_and_restart(r, engine, api, new_zip)
    w = k.world(engine, api, PASSWORD)
    admin_role = k.seeding(r, w, db, dbname, [("rbac-e2e-" + key, uid) for key, uid in early.items()])
    if admin_role is None:
        return

    for key in ("A", "A2", "B", "B2"):
        cid = b.new_id()
        ok, detail = b.create_channel(api, cid, f"rbac e2e {key}")
        r.check(f"create channel {key}", ok, detail)
        w.channels[key] = cid
    w.roles = {
        "viewer": b.create_role(api, "e2e read-only", ["viewChannels", "viewDashboard"]),
        "channel-a": b.create_role(api, "e2e channels A and A2 only", ["viewChannels", "viewDashboard", "manageChannels"],
                                   [w.channels["A"], w.channels["A2"]]),
        "role-viewer": b.create_role(api, "e2e view roles", ["View Roles"]),
        "role-manager": b.create_role(api, "e2e manage roles", ["View Roles", "Manage Roles"]),
        "pruner-view": b.create_role(api, "e2e Data Pruner view", ["View Settings"]),
        "pruner-all": b.create_role(api, "e2e Data Pruner view and start", ["View Settings", "Start / Stop"]),
        "exporter": b.create_role(api, "e2e export roles", ["Export Roles", "View Roles"]),
        "export-only": b.create_role(api, "e2e export roles only", ["Export Roles"]),
        "importer": b.create_role(api, "e2e import roles", ["Import Roles", "Manage Roles"]),
        "import-only": b.create_role(api, "e2e import roles only", ["Import Roles"]),
    }
    for key, uid in early.items():
        k.add_user(w, key, uid=uid)
    for key in ("viewer", "channel-a", "role-viewer", "role-manager", "pruner-view", "pruner-all", "exporter",
                "export-only", "importer", "import-only"):
        k.add_user(w, key, key)
    k.add_user(w, "no-role")

    k.role_crud(r, w)
    k.admin_floor(r, w, admin_role)
    k.matrix(r, w)
    k.data_pruner(r, w)
    k.export_import(r, w)
    k.cache(r, w)
    k.unknown_operations(r, engine)

    # Deleting an engine user leaves its rbac row (rbac_user_role has no foreign key to the engine's users);
    # the sweep at the next start removes it.
    orphan = b.create_user(api, "rbac-e2e-orphan", PASSWORD)
    b.assign_role(api, orphan, w.roles["viewer"])
    status, _ = api.request("DELETE", f"/users/{orphan}")
    r.check("a user holding a role can be deleted", status in (200, 204), f"HTTP {status} {api.reason}")
    rows = db.user_role_rows(dbname, orphan)
    if rows is not None:
        r.check("before the restart, the deleted user's rbac_user_role row is still there", rows == 1, f"found {rows}")

    before_roles = b.roles(api)
    before_users = {key: (b.user_role(api, uid) or {}).get("id") for key, uid in w.ids.items()}
    log_len = len(engine.log())
    api = engine.restart()
    after = engine.log()[log_len:]
    r.check("after a restart, the deleted user's role assignment is gone", b.user_role(api, orphan) is None)
    rows = db.user_role_rows(dbname, orphan)
    if rows is not None:
        r.check("after a restart, the deleted user's rbac_user_role row is gone", rows == 0, f"found {rows}")
    r.check("after a restart, every role is unchanged", b.roles(api) == before_roles)
    after_users = {key: (b.user_role(api, uid) or {}).get("id") for key, uid in w.ids.items()}
    r.check("after a restart, every user keeps its role", after_users == before_users, f"{before_users} -> {after_users}")
    r.check("after a restart, no schema step ran", "Applying RBAC schema" not in after)
    check_schema_version(r, db, dbname, "after a restart: ")
    k.expect(r, "after a restart, read-only is still refused server settings", login(engine, "rbac-e2e-viewer"),
             "GET", "/server/settings", (403,), k.missing("viewServerSettings"))
    check_logs(r, engine)


# ---------- upgrade from a published release

def upgrade(r, engine, db, dbname, new_zip, old_zip, upgrade_engine=None, **_):
    api = engine.start()
    early = b.create_user(api, "rbac-e2e-early-1", PASSWORD)
    # Whether the old release is loaded is read after the lockout check: reading it needs admin to get in.
    api = install_and_restart(r, engine, api, old_zip, check_loaded=False)
    old_version = zip_versions(old_zip)[0]

    status, _ = api.request("GET", b.RBAC + "/roles")
    locked = status == 403
    if not locked:
        check_plugin_loaded(r, api, old_zip)
    if locked:
        # Measured 2026-10-25: 1.1.2 can't create its admin role on Oracle (issue #10), so every user is refused.
        known = old_version == "1.1.2" and db.kind == "oracle"
        r.check("the old release locks admin out only in the known case, 1.1.2 on Oracle", known,
                f"HTTP {status} {api.reason}")
        r.note("old release", f"{old_version} on {db.kind} left no admin role; admin is refused ({api.reason}). "
                              "Nothing is set up on it; the check is that the new release recovers")
        snapshot = users = None
    else:
        channel = b.new_id()
        ok, detail = b.create_channel(api, channel, "rbac e2e upgrade A")
        r.check("create channel A on the old release", ok, detail)
        rid = b.create_role(api, "e2e upgrade channel A", ["viewChannels", "viewDashboard"], [channel])
        viewer = b.create_user(api, "rbac-e2e-viewer", PASSWORD)
        b.assign_role(api, viewer, rid)
        snapshot = b.roles(api)
        users = {uid: (b.user_role(api, uid) or {}).get("id") for uid in ("1", early, viewer)}
        api = engine.restart()
        r.check("the old release keeps its roles across a restart", b.roles(api) == snapshot)

    old_engine, skipped = engine, []
    if upgrade_engine:
        engine.stop()
        engine = upgrade_engine(engine)
        api = engine.start()
        meta = b.plugin_meta(api)
        r.check("on the new engine, the old release is not loaded (it is built for the old engine)", meta is None,
                str(meta))
        # Control: the old release is still installed under the upgraded engine, which skips it.
        skipped = [line for line in engine.plugin_log_lines("ERROR") if "is not compatible" in line]
        r.check("after the engine upgrade: the engine skipped the old release", len(skipped) == 1,
                f"{len(skipped)} 'is not compatible' lines")
        if not locked:
            status, _ = login(engine, "rbac-e2e-viewer").request("GET", "/server/settings")
            r.note("while rbac is unloaded", f"a read-only user gets HTTP {status} for server settings "
                                             "(the engine's allow-all fallback)")

    log_len = len(engine.log())
    api = install_and_restart(r, engine, api, new_zip)
    after = engine.log()[log_len:]
    admin_role = b.admin_role(api)
    r.check("the new release has exactly one admin role", admin_role is not None, str(b.roles(api)))
    if locked:
        r.check("the new release created the admin role the old one couldn't", "Created admin role" in after)
        for name, uid in (("admin", "1"), ("rbac-e2e-early-1", early)):
            got = b.user_role(api, uid)
            r.check(f"{name} holds the admin role again", admin_role and got and got["id"] == admin_role["id"], str(got))
    else:
        # Releases before schema step v3 left SQL Server's text columns VARCHAR; no other database needs a step.
        steps = re.findall(r"Applying RBAC schema (v\d)", after)
        want = ["v3"] if db.server == "sqlserver" else []
        r.check(f"the upgrade ran schema steps {want}", steps == want, f"ran {steps}")
        now = b.roles(api)
        others = {rid: role for rid, role in snapshot.items() if not role["isAdmin"]}
        r.check("every non-admin role is kept as it was", {rid: now.get(rid) for rid in others} == others,
                f"{others} -> {now}")
        old_admin = next(role for role in snapshot.values() if role["isAdmin"])
        r.check("the admin role is kept, flagged, with at least its permissions",
                admin_role and admin_role["id"] == old_admin["id"]
                and admin_role["permissions"] >= old_admin["permissions"], str(admin_role))
        now_users = {uid: (b.user_role(api, uid) or {}).get("id") for uid in users}
        r.check("every user keeps its role", now_users == users, f"{users} -> {now_users}")
        viewer = login(engine, "rbac-e2e-viewer")
        k.expect(r, "after the upgrade, the channel-limited user is still refused server settings", viewer, "GET",
                 "/server/settings", (403,), k.missing("viewServerSettings"))
        status, ids = b.channel_ids(viewer)
        r.check("after the upgrade, the channel-limited user still sees only its channel",
                status == 200 and ids == {channel}, f"HTTP {status}: {ids}")
    k.unicode_role_name(r, api, "after the upgrade: ")
    check_schema_version(r, db, dbname, "after the upgrade: ")
    # 1.1.2's failed seed on Oracle is the known defect above.
    seed_failure = (r"Failed to seed admin permissions; RBAC bootstrap is incomplete",) if locked else ()
    if upgrade_engine:
        check_logs(r, old_engine, allowed=seed_failure, where=" (old engine)")
    check_logs(r, engine, allowed=seed_failure + tuple(re.escape(line) for line in skipped))


# ---------- uninstall and reinstall

def uninstall(r, engine, db, dbname, new_zip, **_):
    api = engine.start()
    api = install_and_restart(r, engine, api, new_zip)
    rid = b.create_role(api, "e2e uninstall read-only", ["viewChannels"])
    viewer = b.create_user(api, "rbac-e2e-viewer", PASSWORD)
    b.assign_role(api, viewer, rid)
    check_tables(r, db, dbname, 4, "before the uninstall: ")
    # Controls for the 'gone' checks below: the same calls must see rbac while it is installed.
    r.check("rbac's extension folder exists before the uninstall", engine.extension_files(b.PLUGIN_PATH) is not None)
    k.expect(r, "before the uninstall, read-only is refused server settings", login(engine, "rbac-e2e-viewer"), "GET",
             "/server/settings", (403,), k.missing("viewServerSettings"))

    ok, detail = b.uninstall(api)
    r.check("uninstall rbac", ok, detail)
    api = engine.restart()
    r.check("rbac is not loaded after the uninstall", b.plugin_meta(api) is None)
    r.check("its extension folder is gone", engine.extension_files(b.PLUGIN_PATH) is None)
    check_tables(r, db, dbname, 0, "after the uninstall: ")
    leftover = db.schema_version(dbname)
    if leftover is not None:
        r.note("after the uninstall", f"schema_version {leftover} is left in CONFIGURATION (the engine doesn't clear it)")
    status, _ = login(engine, "rbac-e2e-viewer").request("GET", "/server/settings")
    r.note("after the uninstall", f"the former read-only user gets HTTP {status} for server settings "
                                  "(the engine's allow-all fallback)")

    log_len = len(engine.log())
    api = install_and_restart(r, engine, api, new_zip)
    after = engine.log()[log_len:]
    r.check("reinstall: the schema is created again despite the old schema_version", "Applying RBAC schema v1" in after)
    check_tables(r, db, dbname, 4, "reinstall: ")
    check_schema_version(r, db, dbname, "reinstall: ")
    now = b.roles(api)
    admin_role = b.admin_role(api)
    r.check("reinstall: only the seeded admin role exists", admin_role is not None and list(now) == [admin_role["id"]],
            str(now))
    got = b.user_role(api, viewer)
    r.check("reinstall: the former read-only user is in the admin role, like every existing user on a first install",
            admin_role and got and got["id"] == admin_role["id"], str(got))
    check_logs(r, engine)
