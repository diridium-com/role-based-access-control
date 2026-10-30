# SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
# SPDX-License-Identifier: MPL-2.0

"""The fresh scenario's checks, one function per feature. Each takes the Report and a World: the engine, the
admin's session, the test users' sessions and ids, the roles and the channels the scenario made."""

import types

import rbac as b
from oie import Api

# rbac refuses with HTTP 403 and puts the reason in the status line (measured on OIE 4.7.0).
NO_ROLE = "Missing permission: any (no role assigned)"


def missing(permission):
    return f"Missing permission: {permission}"


def expect(r, label, api, method, path, statuses, reason=None, body=None, query=None, content_type="application/xml"):
    """One call as one user. statuses: the HTTP statuses that pass. reason: the exact reason phrase wanted,
    checked only when given. Returns (status, text)."""
    status, text = api.request(method, path, body, content_type=content_type, query=query)
    ok = status in statuses and (reason is None or api.reason == reason)
    r.check(label, ok, f"HTTP {status} {api.reason!r}: {text[:150]}")
    return status, text


def world(engine, api, password):
    return types.SimpleNamespace(engine=engine, api=api, password=password, users={}, ids={}, roles={},
                                 channels={})


def add_user(w, key, role_key=None, uid=None):
    """Engine user rbac-e2e-<key>, created unless uid says it exists, assigned the role w.roles[role_key] when
    given, and logged in. Its session and id go in w.users[key] and w.ids[key]."""
    name = "rbac-e2e-" + key
    if uid is None:
        uid = b.create_user(w.api, name, w.password)
    if role_key:
        status, text = b.assign_role(w.api, uid, w.roles[role_key])
        if status not in (200, 204):
            raise RuntimeError(f"assign {role_key} to {name}: HTTP {status} {w.api.reason}: {text[:200]}")
    session = Api(w.engine.port, name, w.password)
    session.login(wait=60)
    w.users[key], w.ids[key] = session, uid
    return session


# ---------- first install: seeding

def seeding(r, w, db, dbname, early_users):
    """The tables, the schema version, and the admin role with every user that existed before the install."""
    log = w.engine.log()
    for step in ("Applying RBAC schema v1", "Applying RBAC schema v2"):
        r.check(f"mirth.log: {step}", step in log)
    tables = db.plugin_table_count(dbname)
    if tables is None:
        r.note("tables", "not read for Derby (embedded in the engine); the REST checks still run")
    else:
        r.check("rbac's four tables exist", tables == 4, f"found {tables}")
        version = db.schema_version(dbname)
        r.check("schema_version is 3 in CONFIGURATION", version == 3, f"found {version}")
    admin_role = b.admin_role(w.api)
    r.check("exactly one role carries the admin flag", admin_role is not None, str(b.roles(w.api)))
    if admin_role is None:
        return None
    r.check("the admin role is the seeded Administrator", admin_role["name"] == "Administrator", admin_role["name"])
    for name, uid in [("admin", "1")] + early_users:
        got = b.user_role(w.api, uid)
        r.check(f"{name}, a user before the install, holds the admin role", got and got["id"] == admin_role["id"],
                str(got))
    return admin_role


# ---------- roles over REST, on this database

def role_crud(r, w, known_issue=None):
    """Create, read, update and delete. The name has characters outside Latin-1, for the database's character
    set; creating a role on Oracle is what failed in 1.1.2 (issue #10). known_issue: an open issue that makes the
    name checks fail on this database. Only the checks that depend on the stored name become NOTEs then
    (Report.known); everything else stays a check."""
    a, chans = w.api, w.channels

    def name_check(label, ok, detail):
        if known_issue:
            r.known(label, ok, known_issue, detail)
        else:
            r.check(label, ok, detail)

    name = "e2e Rôle ünïcödé 角色"
    perms = {"viewChannels", "viewDashboard", "viewMessages", "viewAlerts", "View Roles"}
    rid = b.create_role(a, name, sorted(perms), [chans["A"], chans["B"]])
    got = b.roles(a).get(rid) or {}
    r.check("a created role reads back with its permissions and channels",
            got.get("permissions") == perms and got.get("channelIds") == {chans["A"], chans["B"]}, str(got))
    name_check("a created role reads back with its name, characters outside Latin-1 included",
               got.get("name") == name, repr(got.get("name")))
    status, _ = b.post_role(a, b.role_xml(name, ["viewChannels"]))
    name_check("a second role with the same name is refused (409)", status == 409, f"HTTP {status} {a.reason}")
    new_perms = {"viewChannels", "manageChannels"}
    status, text = b.put_role(a, rid, b.role_xml(name + " 2", sorted(new_perms), [chans["A"]], description="changed"))
    got = b.roles(a).get(rid) or {}
    r.check("an update changes the description, permissions and channels",
            status in (200, 204) and got.get("description") == "changed" and got.get("permissions") == new_perms
            and got.get("channelIds") == {chans["A"]}, f"HTTP {status}: {got}")
    name_check("an update changes the name", got.get("name") == name + " 2", repr(got.get("name")))
    status, _ = b.delete_role(a, rid)
    r.check("a role can be deleted", status in (200, 204) and rid not in b.roles(a), f"HTTP {status}")
    status, _ = a.request("GET", f"{b.RBAC}/roles/{rid}")
    r.check("a deleted role is gone (404)", status == 404, f"HTTP {status}")


def unicode_role_name(r, api, where=""):
    """A role name with characters outside Latin-1 reads back intact, and a second role with it is refused. On
    SQL Server this needs the NVARCHAR columns of schema step v3."""
    name = "e2e Rôle ünïcödé 角色 v3"
    rid = b.create_role(api, name, ["viewChannels"])
    got = (b.roles(api).get(rid) or {}).get("name")
    r.check(f"{where}a role name with characters outside Latin-1 reads back intact", got == name, repr(got))
    status, _ = b.post_role(api, b.role_xml(name, ["viewChannels"]))
    r.check(f"{where}a second role with that name is refused (409)", status == 409, f"HTTP {status} {api.reason}")
    b.delete_role(api, rid)


# ---------- the admin floor

def admin_floor(r, w, admin_role):
    """Three users hold the admin role after the install: admin, early-1 and early-2. Two can leave it; the
    last one can't, and can't be deleted, even by an admin."""
    a, admin_id = w.api, admin_role["id"]
    early1, early2 = w.ids["early-1"], w.ids["early-2"]
    status, _ = b.assign_role(a, early2, w.roles["viewer"])
    r.check("an admin user can be moved to another role while other admins remain", status in (200, 204),
            f"HTTP {status} {a.reason}")
    status, _ = b.remove_role(a, early1)
    r.check("an admin user's role can be removed while another admin remains", status in (200, 204),
            f"HTTP {status} {a.reason}")
    status, text = b.remove_role(a, "1")
    r.check("the last admin's role can't be removed (400)",
            status == 400 and "last admin" in text, f"HTTP {status}: {text[:150]}")
    status, text = b.assign_role(a, "1", w.roles["viewer"])
    r.check("the last admin can't be moved to another role (400)",
            status == 400 and "last admin" in text, f"HTTP {status}: {text[:150]}")
    expect(r, "the last admin user can't be deleted, even by an admin (403)", a, "DELETE", "/users/1", (403,),
           "Cannot delete the last administrator; assign another user to the Administrator role first")
    r.check("admin still holds the admin role", (b.user_role(a, "1") or {}).get("id") == admin_id)
    status, _ = b.assign_role(a, early1, admin_id)
    r.check("a user can be given the admin role", status in (200, 204), f"HTTP {status} {a.reason}")

    status, text = b.delete_role(a, admin_id)
    r.check("the admin role can't be deleted (400)", status == 400 and "admin role" in text,
            f"HTTP {status}: {text[:150]}")
    role = b.roles(a)[admin_id]
    fewer = sorted(role["permissions"] - {"viewChannels"})
    status, text = b.put_role(a, admin_id, b.role_xml(role["name"], fewer, is_admin=True))
    r.check("the admin role can't lose a permission (400)", status == 400 and "retain" in text,
            f"HTTP {status}: {text[:150]}")
    status, text = b.put_role(a, admin_id, b.role_xml(role["name"], sorted(role["permissions"]), [w.channels["A"]],
                                                      is_admin=True))
    r.check("the admin role can't be limited to channels (400)", status == 400 and "channel" in text,
            f"HTTP {status}: {text[:150]}")


# ---------- what each role can and can't do

def matrix(r, w):
    u, c = w.users, w.channels
    norole, viewer, chans = u["no-role"], u["viewer"], u["channel-a"]

    # No role: refused, except the calls rbac allows every signed-in user.
    expect(r, "no role: /users/current is refused", norole, "GET", "/users/current", (403,), NO_ROLE)
    expect(r, "no role: server settings are refused", norole, "GET", "/server/settings", (403,), NO_ROLE)
    expect(r, "no role: /server/status is allowed", norole, "GET", "/server/status", (200,))
    status, perms = b.my_permissions(norole)
    r.check("no role: my-permissions is allowed and empty", status == 200 and perms == set(), f"HTTP {status}: {perms}")
    status, ids = b.channel_ids(norole)
    r.check("no role: /channels answers with an empty list (the engine's own fallback)", status == 200 and ids == set(),
            f"HTTP {status}: {ids}")

    # Read-only: reads work, changes and other areas are refused with the permission named.
    status, ids = b.channel_ids(viewer)
    r.check("read-only: /channels lists every channel", status == 200 and set(c.values()) <= ids, f"HTTP {status}")
    expect(r, "read-only: server settings are refused", viewer, "GET", "/server/settings", (403,),
           missing("viewServerSettings"))
    expect(r, "read-only: creating a user is refused", viewer, "POST", "/users",
           (403,), missing("manageUsers"), body="<user><username>rbac-e2e-x</username></user>")
    expect(r, "read-only: removing a channel is refused", viewer, "DELETE", f"/channels/{c['B']}", (403,),
           missing("manageChannels"))
    expect(r, "read-only: rbac's role list is refused", viewer, "GET", b.RBAC + "/roles", (403,), missing("View Roles"))
    status, perms = b.my_permissions(viewer)
    r.check("read-only: my-permissions lists its role's grants", perms == {"viewChannels", "viewDashboard"},
            f"HTTP {status}: {perms}")

    # Users: without manageUsers, /users shows only yourself, and only your own password can change.
    status, names = b.visible_users(viewer)
    r.check("read-only: /users shows only its own record", status == 200 and names == ["rbac-e2e-viewer"],
            f"HTTP {status}: {names}")
    expect(r, "read-only: changing its own password is allowed", viewer, "PUT", f"/users/{w.ids['viewer']}/password",
           (200, 204), body=w.password, content_type="text/plain")
    expect(r, "read-only: changing another user's password is refused", viewer, "PUT",
           f"/users/{w.ids['no-role']}/password", (403,), missing("manageUsers"), body=w.password,
           content_type="text/plain")

    # Channel restrictions, as the engine applies them: lists filtered, single-channel reads refused,
    # bulk changes silently limited to the allowed channels.
    allowed = {c["A"], c["A2"]}
    status, ids = b.channel_ids(chans)
    r.check("channel-limited: /channels lists only its channels", status == 200 and ids == allowed, f"HTTP {status}: {ids}")
    status, ids = b.ids_and_names(chans)
    r.check("channel-limited: idsAndNames lists only its channels", status == 200 and ids == allowed,
            f"HTTP {status}: {ids}")
    expect(r, "channel-limited: its own channel's statistics are readable", chans, "GET",
           f"/channels/{c['A']}/statistics", (200, 204))
    expect(r, "channel-limited: another channel's statistics are refused", chans, "GET",
           f"/channels/{c['B']}/statistics", (403,))
    status, _ = chans.request("DELETE", "/channels", query={"channelId": [c["A2"], c["B2"]]})
    _, ids = b.channel_ids(w.api)
    r.check("channel-limited: a bulk remove of an allowed and a disallowed channel removes only the allowed one",
            status in (200, 204) and ids is not None and c["A2"] not in ids and c["B2"] in ids,
            f"HTTP {status}; admin sees {ids}")

    # rbac's own servlet: View Roles reads, Manage Roles changes; neither makes an admin.
    rv, rm = u["role-viewer"], u["role-manager"]
    expect(r, "View Roles: the role list is allowed", rv, "GET", b.RBAC + "/roles", (200,))
    expect(r, "View Roles: creating a role is refused", rv, "POST", b.RBAC + "/roles", (403,), missing("Manage Roles"),
           body=b.role_xml("e2e by role-viewer", ["viewChannels"]))
    expect(r, "View Roles: assigning a role is refused", rv, "POST",
           f"{b.RBAC}/users/{w.ids['no-role']}/role/{w.roles['viewer']}", (403,), missing("Manage Roles"))
    status, text = b.post_role(rm, b.role_xml("e2e made admin by role-manager", ["viewChannels"], is_admin=True))
    made = [x for x in b.roles(w.api).values() if x["name"] == "e2e made admin by role-manager"]
    r.check("Manage Roles: a role created with the admin flag is stored without it",
            status in (200, 201) and len(made) == 1 and not made[0]["isAdmin"], f"HTTP {status}: {made}")
    status, text = b.delete_role(rm, b.admin_role(w.api)["id"])
    r.check("Manage Roles: the admin role can't be deleted (400)", status == 400, f"HTTP {status}: {text[:150]}")

    # A second user in the admin role gets everything, like admin.
    early1 = u["early-1"]
    for path in ("/server/settings", b.RBAC + "/roles", b.DATA_PRUNER + "/status"):
        expect(r, f"second admin user: GET {path} is allowed", early1, "GET", path, (200,))


def data_pruner(r, w):
    """An extension bundled with the engine, gated by its own grants: rbac enforces extension operations
    for an extension other than itself."""
    u, dp = w.users, b.DATA_PRUNER
    expect(r, "no Data Pruner grants: its status is refused", u["viewer"], "GET", dp + "/status", (403,),
           missing("View Settings"))
    expect(r, "View Settings: Data Pruner's status is allowed", u["pruner-view"], "GET", dp + "/status", (200,))
    expect(r, "View Settings: starting Data Pruner is refused", u["pruner-view"], "POST", dp + "/_start", (403,),
           missing("Start / Stop"))
    expect(r, "View Settings + Start / Stop: starting Data Pruner is allowed", u["pruner-all"], "POST", dp + "/_start",
           (200, 204))
    expect(r, "View Settings + Start / Stop: stopping Data Pruner is allowed", u["pruner-all"], "POST", dp + "/_stop",
           (200, 204))


def export_import(r, w):
    """Roles out to a file and back in: who may, what the file contains, the preview, only the picked roles written,
    the channel choice, roles that can't come in, and refused files that write nothing."""
    a, u, imp = w.api, w.users, w.users["importer"]
    t1, t2 = b.new_id(), b.new_id()
    for cid, name in ((t1, "rbac e2e T1"), (t2, "rbac e2e T2")):
        ok, detail = b.create_channel(a, cid, name)
        r.check(f"create channel {name}", ok, detail)
    restricted = b.create_role(a, "e2e transfer restricted", ["viewChannels", "viewDashboard"], [t1, t2])
    unrestricted = b.create_role(a, "e2e transfer open", ["viewChannels"])

    def by_name():
        return {role["name"]: role for role in b.roles(a).values()}

    def refused(label, api, status, permission):
        r.check(label, status == 403 and api.reason == missing(permission), f"HTTP {status} {api.reason!r}")

    def preview(text, apply_channels=True, label="the preview"):
        status, body = b.import_roles(imp, text, apply_channels=apply_channels)
        r.check(f"import: {label} answers", status == 200, f"HTTP {status} {imp.reason!r}: {body[:200]}")
        return b.parse_import(body) if status == 200 else {"importable": False, "rows": {}, "token": None}

    def apply(text, plan, names, apply_channels=True):
        pick = [plan["rows"][n]["index"] for n in names if n in plan["rows"]]
        return b.import_roles(imp, text, dry_run=False, apply_channels=apply_channels, pick=pick, token=plan["token"])

    # Export: who may, and what the file contains.
    refused("export: View Roles without Export Roles is refused", u["role-viewer"],
            b.export_roles(u["role-viewer"])[0], "Export Roles")
    refused("export: Export Roles without View Roles is refused", u["export-only"],
            b.export_roles(u["export-only"])[0], "View Roles")
    status, text = b.export_roles(u["exporter"], [restricted, unrestricted])
    r.check("export: Export Roles with View Roles may export", status == 200, f"HTTP {status}: {text[:200]}")
    header, exported = b.parse_export(text) if status == 200 else ({}, {})
    r.check("export: the file says format 1 and the rbac version that wrote it",
            header.get("formatVersion") == "1" and header.get("rbacVersion") == b.plugin_meta(a)[0], str(header))
    r.check("export: the file has the chosen roles and no others",
            set(exported) == {"e2e transfer restricted", "e2e transfer open"}, str(set(exported)))
    got = exported.get("e2e transfer restricted", {})
    r.check("export: a restricted role carries its permissions and its channels by id and name",
            got.get("permissions") == {"viewChannels", "viewDashboard"} and got.get("restricted") is True
            and got.get("channels") == {t1: "rbac e2e T1", t2: "rbac e2e T2"}, str(got))
    r.check("export: an unrestricted role says every channel",
            exported.get("e2e transfer open", {}).get("restricted") is False, str(exported.get("e2e transfer open")))
    status, everything = b.export_roles(a)
    names = set(b.parse_export(everything)[1]) if status == 200 else set()
    r.check("export: with no ids, the file has every role but the admin role",
            names == {role["name"] for role in b.roles(a).values() if not role["isAdmin"]}, str(names))
    status, body = b.export_roles(a, [b.admin_role(a)["id"]])
    r.check("export: the admin role is refused (400)", status == 400 and "never exported" in body, f"HTTP {status}: {body}")

    # Import: who may.
    refused("import: Manage Roles without Import Roles is refused", u["role-manager"],
            b.import_roles(u["role-manager"], text)[0], "Import Roles")
    refused("import: Import Roles without Manage Roles is refused", u["import-only"],
            b.import_roles(u["import-only"], text)[0], "Manage Roles")

    # A round trip: delete both roles, preview, apply.
    for rid in (restricted, unrestricted):
        b.delete_role(a, rid)
    plan = preview(text)
    r.check("import: the preview plans both deleted roles as new",
            {n: row["action"] for n, row in plan["rows"].items()}
            == {"e2e transfer restricted": "CREATE", "e2e transfer open": "CREATE"}, str(plan["rows"]))
    r.check("import: a preview writes nothing", "e2e transfer restricted" not in by_name())
    status, body = apply(text, plan, ["e2e transfer restricted", "e2e transfer open"])
    now = by_name()
    r.check("import: the apply writes the roles", status == 200 and b.parse_import(body)["applied"],
            f"HTTP {status}: {body[:200]}")
    got = now.get("e2e transfer restricted", {})
    r.check("import: the restricted role comes back with its permissions and channels",
            got.get("permissions") == {"viewChannels", "viewDashboard"} and got.get("channelIds") == {t1, t2}, str(got))
    got = now.get("e2e transfer open", {})
    r.check("import: the unrestricted role comes back seeing every channel",
            got.get("permissions") == {"viewChannels"} and got.get("channelIds") == set(), str(got))
    again = preview(text, label="a second preview")
    r.check("import: a second preview finds both roles unchanged",
            {row["action"] for row in again["rows"].values()} == {"UNCHANGED"}, str(again["rows"]))

    # Only the picked roles are written.
    picked = b.role_file([("e2e transfer open", ["viewChannels", "viewMessages"], None),
                          ("e2e transfer picked", ["viewChannels"], None)])
    plan = preview(picked)
    r.check("import: a changed role is planned as an overwrite",
            plan["rows"].get("e2e transfer open", {}).get("action") == "OVERWRITE", str(plan["rows"]))
    status, _ = apply(picked, plan, ["e2e transfer picked"])
    now = by_name()
    r.check("import: only the picked role is written",
            status == 200 and "e2e transfer picked" in now
            and now["e2e transfer open"]["permissions"] == {"viewChannels"}, f"HTTP {status}")

    # Channel restrictions not applied: an existing role keeps its own, a new one sees every channel.
    off = b.role_file([("e2e transfer restricted", ["viewChannels"], [(t1, "rbac e2e T1")]),
                       ("e2e transfer everywhere", ["viewChannels"], [(t1, "rbac e2e T1")])])
    plan = preview(off, apply_channels=False, label="a preview without channel restrictions")
    rows = plan["rows"]
    r.check("import without channels: the existing role keeps its channels, the new one sees every channel",
            rows.get("e2e transfer restricted", {}).get("channels") == "KEPT"
            and rows.get("e2e transfer everywhere", {}).get("channels") == "EVERY_CHANNEL"
            and "Sees every channel" in (rows.get("e2e transfer everywhere", {}).get("reason") or ""), str(rows))
    status, _ = apply(off, plan, ["e2e transfer restricted", "e2e transfer everywhere"], apply_channels=False)
    now = by_name()
    r.check("import without channels: the overwritten role has the new permissions and its old channels",
            status == 200 and now["e2e transfer restricted"]["permissions"] == {"viewChannels"}
            and now["e2e transfer restricted"]["channelIds"] == {t1, t2}, f"HTTP {status}: {now.get('e2e transfer restricted')}")
    r.check("import without channels: the new role sees every channel",
            now.get("e2e transfer everywhere", {}).get("channelIds") == set(), str(now.get("e2e transfer everywhere")))

    # Roles that can't come in, and a permission this engine doesn't offer.
    mixed = b.role_file([("e2e transfer gone", ["viewChannels"], [(b.new_id(), "rbac e2e no such channel")]),
                         ("Administrator", ["viewChannels"], None),
                         ("e2e transfer unknown permission", ["viewChannels", "e2e No Such Permission"], None)])
    plan = preview(mixed)
    rows = plan["rows"]
    r.check("import: a restricted role none of whose channels exist is skipped, with the reason",
            rows.get("e2e transfer gone", {}).get("action") == "SKIP"
            and "None of its 1 channels exist" in (rows.get("e2e transfer gone", {}).get("reason") or ""), str(rows))
    r.check("import: the admin role's name is skipped",
            rows.get("Administrator", {}).get("action") == "SKIP", str(rows.get("Administrator")))
    r.check("import: a permission this engine doesn't offer is listed",
            rows.get("e2e transfer unknown permission", {}).get("dropped") == ["e2e No Such Permission"], str(rows))
    status, body = apply(mixed, plan, ["e2e transfer gone"])
    r.check("import: picking a skipped role is refused (400) and writes nothing",
            status == 400 and "e2e transfer gone" not in by_name(), f"HTTP {status}: {body[:200]}")
    status, _ = apply(mixed, plan, ["e2e transfer unknown permission"])
    got = by_name().get("e2e transfer unknown permission", {})
    r.check("import: the permission this engine doesn't offer is left out",
            status == 200 and got.get("permissions") == {"viewChannels"}, f"HTTP {status}: {got}")

    # Refused files write nothing.
    before = b.roles(a)
    newer = b.role_file([("e2e transfer newer", ["viewChannels"], None)], format_version="2")
    plan = preview(newer, label="a preview of a newer format")
    r.check("import: a newer format is refused, with the reason",
            not plan["importable"]
            and plan.get("refusal") == "This file is format 2, written by rbac e2e. This rbac reads format 1.",
            str(plan.get("refusal")))
    doctype = ('<?xml version="1.0"?><!DOCTYPE rbacRoles [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
               + b.role_file([("e2e transfer &x;", ["viewChannels"], None)]).replace("&amp;x;", "&x;"))
    for label, bad, reason in (("a newer format", newer, "This file is format 2"),
                               ("a DOCTYPE", doctype, "The file has a DOCTYPE."),
                               ("a damaged file", text[:len(text) // 2], "isn't well-formed XML")):
        status, body = b.import_roles(imp, bad, dry_run=False, pick=[0], token="x")
        r.check(f"import: applying {label} is refused (400) with the reason", status == 400 and reason in body,
                f"HTTP {status}: {body[:200]}")
    r.check("import: refused files write nothing", b.roles(a) == before)

    # The roles changed between the preview and the apply.
    stale = b.role_file([("e2e transfer open", ["viewChannels", "viewAlerts"], None)])
    plan = preview(stale)
    b.put_role(a, by_name()["e2e transfer open"]["id"], b.role_xml("e2e transfer open", ["viewChannels"],
                                                                     description="changed after the preview"))
    status, body = apply(stale, plan, ["e2e transfer open"])
    r.check("import: an apply after the roles changed is refused (409) and writes nothing",
            status == 409 and "Preview the import again" in body
            and by_name()["e2e transfer open"]["permissions"] == {"viewChannels"}, f"HTTP {status}: {body[:200]}")

    # Two new names that differ only by an accent. The file compares names ignoring case only, so both are planned
    # as new; a database whose names also ignore accents (MySQL's default collation) treats them as one name. There
    # the apply stops on the second, says why, and writes neither. The NOTE says which happened.
    accents = ("e2e transfer Café", "e2e transfer Cafe")
    pair = b.role_file([(name, ["viewChannels"], None) for name in accents])
    plan = preview(pair, label="a preview of two names that differ only by an accent")
    status, body = apply(pair, plan, accents)
    written = [name for name in accents if name in by_name()]
    r.check("import: two names that differ only by an accent are both written, or refused (400) with the reason"
            " and neither written",
            (status == 200 and len(written) == 2)
            or (status == 400 and "Rename one of them in the file." in body and not written),
            f"HTTP {status}: {body[:200]}; written: {written}")
    r.note("import of two names that differ only by an accent",
           "both written" if status == 200 else f"HTTP {status}, neither written: {body[:200]}")


def cache(r, w):
    """A change to a role applies to its users' next request, with no restart."""
    viewer, rid = w.users["viewer"], w.roles["viewer"]
    role = b.roles(w.api)[rid]
    expect(r, "cache: before the change, server settings are refused", viewer, "GET", "/server/settings", (403,))
    b.put_role(w.api, rid, b.role_xml(role["name"], sorted(role["permissions"] | {"viewServerSettings"})))
    expect(r, "cache: right after viewServerSettings is granted, server settings are allowed", viewer, "GET",
           "/server/settings", (200,))
    b.put_role(w.api, rid, b.role_xml(role["name"], sorted(role["permissions"])))
    expect(r, "cache: right after it is taken away again, server settings are refused", viewer, "GET",
           "/server/settings", (403,), missing("viewServerSettings"))


def unknown_operations(r, engine):
    """Every operation of rbac's own servlet and of Data Pruner has a permission; none may slip through
    rbac's allow-unknown fallback."""
    for plugin in (b.PLUGIN_NAME, "Data Pruner"):
        lines = [line for line in engine.log().splitlines()
                 if "allowing unknown operation" in line and f"'{plugin}#" in line]
        r.check(f"rbac has a permission for every {plugin} operation used", not lines, " | ".join(lines[:3]))
