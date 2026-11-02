# SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
# SPDX-License-Identifier: MPL-2.0

"""The fresh scenario's role export and import checks. Each takes the Report and a World (checks.world)."""

import os
import time
import types

import rbac as b

# A role export file from an engine on Derby, made by make_derby_roles_fixture.py.
FROM_DERBY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "roles-from-derby.xml")
# Databases whose default collation holds "Lab" and "LAB" as one name (measured on OIE 4.7.0).
ONE_NAME_FOR_BOTH_CASES = ("mysql", "sqlserver")


def export_import(r, w, db_server):
    """Roles out to a file and back in. The parts run in this order because later ones use roles the earlier ones
    wrote: who may, a round trip, what an overwrite changes, channel restrictions not applied, what is refused,
    names the database may hold as one, and a file from another engine."""
    a = w.api
    t = types.SimpleNamespace(t1=b.new_id(), t2=b.new_id())
    for cid, name in ((t.t1, "rbac e2e T1"), (t.t2, "rbac e2e T2")):
        ok, detail = b.create_channel(a, cid, name)
        r.check(f"create channel {name}", ok, detail)
    t.restricted = b.create_role(a, "e2e transfer restricted", ["viewChannels", "viewDashboard"], [t.t1, t.t2])
    t.unrestricted = b.create_role(a, "e2e transfer open", ["viewChannels"])
    _transfer_who_may(r, w, t)
    _transfer_round_trip(r, a, t)
    _transfer_overwrites(r, a, t)
    _transfer_without_channels(r, a, t)
    _transfer_refusals(r, a, t)
    _transfer_names(r, a)
    _transfer_from_another_engine(r, a, db_server)


def _roles_by_name(a):
    return {role["name"]: role for role in b.roles(a).values()}


def _preview(r, a, text, apply_channels=True, label="the preview", match_by_name=False):
    status, body = b.import_roles(a, text, apply_channels=apply_channels, match_by_name=match_by_name)
    r.check(f"import: {label} answers", status == 200, f"HTTP {status} {a.reason!r}: {body[:200]}")
    return b.parse_import(body) if status == 200 else {"importable": False, "rows": {}, "token": None, "matches": []}


def _apply(a, text, plan, names, apply_channels=True, match_by_name=False):
    pick = [plan["rows"][n]["index"] for n in names if n in plan["rows"]]
    return b.import_roles(a, text, dry_run=False, apply_channels=apply_channels, match_by_name=match_by_name,
                          pick=pick, token=plan["token"])


def _waited(find, seconds=30):
    """find()'s first truthy answer within seconds, else its last. The engine stores audit events from a queue."""
    end = time.time() + seconds
    while True:
        found = find()
        if found or time.time() > end:
            return found
        time.sleep(1)


def _transfer_who_may(r, w, t):
    """Only the admin role may export or import. Any other role is refused with the reason, whatever its
    permissions, and the engine's audit records the refusal rather than a successful call. Also what an export
    holds."""
    a, u = w.api, w.users
    for key in ("viewer", "role-viewer", "every-permission"):
        status, _ = b.export_roles(u[key])
        r.check(f"export: {key} without the admin role is refused", status == 403
                and u[key].reason == "Exporting roles needs the admin role.", f"HTTP {status} {u[key].reason!r}")
    export_status, text = b.export_roles(a, [t.restricted, t.unrestricted])
    t.file = text
    r.check("export: the admin role may export", export_status == 200, f"HTTP {export_status}: {text[:200]}")
    r.check("export: the response says its character set is UTF-8",
            "charset=utf-8" in (a.content_type or "").lower().replace(" ", ""), str(a.content_type))
    for key in ("viewer", "role-manager", "every-permission"):
        status, _ = b.import_roles(u[key], text)
        r.check(f"import: {key} without the admin role is refused, a preview included", status == 403
                and u[key].reason == "Importing roles needs the admin role.", f"HTTP {status} {u[key].reason!r}")
    name, uid = "Import roles invoked through " + b.PLUGIN_NAME, w.ids["role-manager"]
    failures = _waited(lambda: b.authorization_events(a, name, uid, "FAILURE"))
    successes = b.authorization_events(a, name, uid, "SUCCESS")
    r.check("import: a refused import is audited as a failure, not as a success", bool(failures) and not successes,
            f"failures {failures}, successes {successes}")

    header, exported = b.parse_export(text) if export_status == 200 else ({}, {})
    r.check("export: the file says format 1 and the rbac version that wrote it",
            header.get("formatVersion") == "1" and header.get("rbacVersion") == b.plugin_meta(a)[0], str(header))
    r.check("export: the file has the chosen roles and no others",
            set(exported) == {"e2e transfer restricted", "e2e transfer open"}, str(set(exported)))
    got = exported.get("e2e transfer restricted", {})
    r.check("export: a restricted role carries its permissions and its channels by id and name",
            got.get("permissions") == {"viewChannels", "viewDashboard"} and got.get("restricted") is True
            and got.get("channels") == {t.t1: "rbac e2e T1", t.t2: "rbac e2e T2"}, str(got))
    r.check("export: an unrestricted role says every channel",
            exported.get("e2e transfer open", {}).get("restricted") is False, str(exported.get("e2e transfer open")))
    status, everything = b.export_roles(a)
    names = set(b.parse_export(everything)[1]) if status == 200 else set()
    r.check("export: with no ids, the file has every role but the admin role",
            names == {role["name"] for role in b.roles(a).values() if not role["isAdmin"]}, str(names))
    status, body = b.export_roles(a, [b.admin_role(a)["id"]])
    r.check("export: the admin role is refused (400)", status == 400 and "never exported" in body, f"HTTP {status}: {body}")
    status, body = a.request("GET", b.RBAC + "/roles/_export", query={"roleId": ""}, accept="text/plain")
    r.check("export: a roleId with no value is refused, not taken as every role", status in (400, 404),
            f"HTTP {status}: {body[:200]}")
    r.note("export with a roleId that has no value", f"HTTP {status}: {body[:120]}")


def _transfer_round_trip(r, a, t):
    """Delete both roles, preview the file, apply it: they come back as they were, and the audit says so."""
    for rid in (t.restricted, t.unrestricted):
        b.delete_role(a, rid)
    plan = _preview(r, a, t.file)
    r.check("import: the preview plans both deleted roles as new",
            {n: row["action"] for n, row in plan["rows"].items()}
            == {"e2e transfer restricted": "CREATE", "e2e transfer open": "CREATE"}, str(plan["rows"]))
    r.check("import: a preview writes nothing", "e2e transfer restricted" not in _roles_by_name(a))
    status, body = _apply(a, t.file, plan, ["e2e transfer restricted", "e2e transfer open"])
    now = _roles_by_name(a)
    r.check("import: the apply writes the roles", status == 200 and b.parse_import(body)["applied"],
            f"HTTP {status}: {body[:200]}")
    got = now.get("e2e transfer restricted", {})
    r.check("import: the restricted role comes back with its permissions and channels",
            got.get("permissions") == {"viewChannels", "viewDashboard"} and got.get("channelIds") == {t.t1, t.t2},
            str(got))
    got = now.get("e2e transfer open", {})
    r.check("import: the unrestricted role comes back seeing every channel",
            got.get("permissions") == {"viewChannels"} and got.get("channelIds") == set(), str(got))
    event = _waited(lambda: next((e for e in b.plugin_events(a, "Role: e2e transfer restricted")
                                  if e.get("Action") == "Imported"), None))
    channels = ", ".join(sorted([f"rbac e2e T1 ({t.t1})", f"rbac e2e T2 ({t.t2})"]))
    r.check("import: the audit event names the roles created and what each was given",
            event is not None
            and event.get("Created") == "e2e transfer restricted, e2e transfer open"
            and event.get("Role: e2e transfer restricted")
            == f"Permissions: viewChannels, viewDashboard. Channels: {channels}."
            and event.get("Role: e2e transfer open") == "Permissions: viewChannels. Channels: every channel.",
            str(event))
    again = _preview(r, a, t.file, label="a second preview")
    r.check("import: a second preview finds both roles unchanged",
            {row["action"] for row in again["rows"].values()} == {"UNCHANGED"}, str(again["rows"]))


def _transfer_overwrites(r, a, t):
    """What a preview says an overwrite changes, and that only the picked roles are written."""
    picked = b.role_file([("e2e transfer open", ["viewChannels", "viewMessages"], None),
                          ("e2e transfer picked", ["viewChannels"], None)])
    plan = _preview(r, a, picked)
    row = plan["rows"].get("e2e transfer open", {})
    r.check("import: a changed role is planned as an overwrite", row.get("action") == "OVERWRITE", str(plan["rows"]))
    r.check("import: the overwrite lists the permission it adds, and nothing else changes",
            row.get("added_permissions") == ["viewMessages"] and row.get("removed_permissions") == []
            and row.get("description_changed") is False and row.get("added_channels") == []
            and row.get("removed_channels") == [], str(row))
    status, _ = _apply(a, picked, plan, ["e2e transfer picked"])
    now = _roles_by_name(a)
    r.check("import: only the picked role is written",
            status == 200 and "e2e transfer picked" in now
            and now["e2e transfer open"]["permissions"] == {"viewChannels"}, f"HTTP {status}")

    narrower = b.role_file([("e2e transfer restricted", ["viewChannels", "viewDashboard"], [(t.t1, "rbac e2e T1")])])
    row = _preview(r, a, narrower, label="a preview that narrows a role's channels")["rows"].get(
        "e2e transfer restricted", {})
    r.check("import: an overwrite lists the channel it takes away, by name",
            row.get("action") == "OVERWRITE" and row.get("removed_channels") == ["rbac e2e T2"]
            and row.get("added_channels") == [] and row.get("added_permissions") == [], str(row))
    wider = b.role_file([("e2e transfer restricted", ["viewChannels", "viewDashboard"], None)])
    row = _preview(r, a, wider, label="a preview that lets a restricted role see every channel")["rows"].get(
        "e2e transfer restricted", {})
    r.check("import: an overwrite that lets a restricted role see every channel says so",
            row.get("action") == "OVERWRITE"
            and row.get("reason") == "Sees every channel after the import; here it is restricted to 2 channel(s).",
            str(row))


def _transfer_without_channels(r, a, t):
    """Channel restrictions not applied: an existing role keeps its own, a new one sees every channel."""
    off = b.role_file([("e2e transfer restricted", ["viewChannels"], [(t.t1, "rbac e2e T1")]),
                       ("e2e transfer everywhere", ["viewChannels"], [(t.t1, "rbac e2e T1")])])
    plan = _preview(r, a, off, apply_channels=False, label="a preview without channel restrictions")
    rows = plan["rows"]
    r.check("import without channels: the existing role keeps its channels, the new one sees every channel",
            rows.get("e2e transfer restricted", {}).get("channels") == "KEPT"
            and rows.get("e2e transfer everywhere", {}).get("channels") == "EVERY_CHANNEL"
            and "Sees every channel" in (rows.get("e2e transfer everywhere", {}).get("reason") or ""), str(rows))
    status, _ = _apply(a, off, plan, ["e2e transfer restricted", "e2e transfer everywhere"], apply_channels=False)
    now = _roles_by_name(a)
    r.check("import without channels: the overwritten role has the new permissions and its old channels",
            status == 200 and now["e2e transfer restricted"]["permissions"] == {"viewChannels"}
            and now["e2e transfer restricted"]["channelIds"] == {t.t1, t.t2},
            f"HTTP {status}: {now.get('e2e transfer restricted')}")
    r.check("import without channels: the new role sees every channel",
            now.get("e2e transfer everywhere", {}).get("channelIds") == set(), str(now.get("e2e transfer everywhere")))


def _transfer_refusals(r, a, t):
    """Roles that can't come in, a permission this engine doesn't offer, refused files that write nothing, and an
    apply after the roles changed."""
    mixed = b.role_file([("e2e transfer gone", ["viewChannels"], [(b.new_id(), "rbac e2e no such channel")]),
                         ("Administrator", ["viewChannels"], None),
                         ("e2e transfer unknown permission", ["viewChannels", "e2e No Such Permission"], None)])
    plan = _preview(r, a, mixed)
    rows = plan["rows"]
    r.check("import: a restricted role none of whose channels exist is skipped, with the reason",
            rows.get("e2e transfer gone", {}).get("action") == "SKIP"
            and "None of its 1 channels exist" in (rows.get("e2e transfer gone", {}).get("reason") or ""), str(rows))
    r.check("import: the admin role's name is skipped",
            rows.get("Administrator", {}).get("action") == "SKIP", str(rows.get("Administrator")))
    r.check("import: a permission this engine doesn't offer is listed",
            rows.get("e2e transfer unknown permission", {}).get("dropped") == ["e2e No Such Permission"], str(rows))
    status, body = _apply(a, mixed, plan, ["e2e transfer gone"])
    r.check("import: picking a skipped role is refused (400) and writes nothing",
            status == 400 and "e2e transfer gone" not in _roles_by_name(a), f"HTTP {status}: {body[:200]}")
    status, _ = _apply(a, mixed, plan, ["e2e transfer unknown permission"])
    got = _roles_by_name(a).get("e2e transfer unknown permission", {})
    r.check("import: the permission this engine doesn't offer is left out",
            status == 200 and got.get("permissions") == {"viewChannels"}, f"HTTP {status}: {got}")

    before = b.roles(a)
    newer = b.role_file([("e2e transfer newer", ["viewChannels"], None)], format_version="2")
    plan = _preview(r, a, newer, label="a preview of a newer format")
    r.check("import: a newer format is refused, with the reason",
            not plan["importable"]
            and plan.get("refusal") == "This file is format 2, written by rbac e2e. This rbac reads format 1.",
            str(plan.get("refusal")))
    doctype = ('<?xml version="1.0"?><!DOCTYPE rbacRoles [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
               + b.role_file([("e2e transfer &x;", ["viewChannels"], None)]).replace("&amp;x;", "&x;"))
    for label, bad, reason in (("a newer format", newer, "This file is format 2"),
                               ("a DOCTYPE", doctype, "The file has a DOCTYPE."),
                               ("a damaged file", t.file[:len(t.file) // 2], "isn't well-formed XML")):
        status, body = b.import_roles(a, bad, dry_run=False, pick=[0], token="x")
        r.check(f"import: applying {label} is refused (400) with the reason", status == 400 and reason in body,
                f"HTTP {status}: {body[:200]}")
    r.check("import: refused files write nothing", b.roles(a) == before)

    stale = b.role_file([("e2e transfer open", ["viewChannels", "viewAlerts"], None)])
    plan = _preview(r, a, stale)
    b.put_role(a, _roles_by_name(a)["e2e transfer open"]["id"],
               b.role_xml("e2e transfer open", ["viewChannels"], description="changed after the preview"))
    status, body = _apply(a, stale, plan, ["e2e transfer open"])
    r.check("import: an apply after the roles changed is refused (409) and writes nothing",
            status == 409 and "Preview the import again" in body
            and _roles_by_name(a)["e2e transfer open"]["permissions"] == {"viewChannels"}, f"HTTP {status}: {body[:200]}")


def _transfer_names(r, a):
    """A name with characters outside Latin-1 out over HTTP and back, and names this database may hold as one."""
    wide = "e2e transfer Rôle 角色"
    wide_id = b.create_role(a, wide, ["viewChannels"])
    status, wide_file = b.export_roles(a, [wide_id])
    names = set(b.parse_export(wide_file)[1]) if status == 200 else set()
    r.check("export: a name with characters outside Latin-1 comes out intact", names == {wide},
            f"HTTP {status}: {names}")
    b.delete_role(a, wide_id)
    plan = _preview(r, a, wide_file, label="a preview of a name with characters outside Latin-1")
    status, body = _apply(a, wide_file, plan, [wide])
    r.check("import: a name with characters outside Latin-1 goes back in intact",
            status == 200 and wide in _roles_by_name(a), f"HTTP {status}: {body[:200]}; planned: {list(plan['rows'])}")

    # Postgres, Derby and Oracle hold "Case" and "CASE" as two roles; MySQL and SQL Server refuse the second (409).
    # Either way an export of every role reads back, and where both exist they go back in as two roles.
    case_pair = ["e2e transfer Case", "e2e transfer CASE"]
    b.create_role(a, case_pair[0], ["viewChannels"])
    status, _ = b.post_role(a, b.role_xml(case_pair[1], ["viewChannels"]))
    both = status in (200, 201)
    r.check("a role whose name differs from another only in case is created, or refused (409)",
            both or status == 409, f"HTTP {status} {a.reason}")
    r.note("a second role whose name differs only in case", "created" if both else f"HTTP {status}")
    status, everything = b.export_roles(a)
    plan = _preview(r, a, everything, label="a preview of every role")
    held = case_pair if both else case_pair[:1]
    cases = {n: row["action"] for n, row in plan["rows"].items() if n in case_pair}
    r.check("import: an export of every role reads back, names that differ only in case included, and plans no"
            " change for them", plan["importable"] and cases == {n: "UNCHANGED" for n in held},
            f"{plan.get('refusal')}: {cases}")
    if both:
        for name in case_pair:
            b.delete_role(a, _roles_by_name(a)[name]["id"])
        plan = _preview(r, a, everything, label="a preview of every role after deleting the two")
        status, body = _apply(a, everything, plan, case_pair)
        now = _roles_by_name(a)
        r.check("import: names that differ only in case go back in as two roles",
                status == 200 and all(name in now for name in case_pair), f"HTTP {status}: {body[:200]}")

    # Two new names that differ only by an accent. The file compares names exactly, so both are planned as new; a
    # database whose names also ignore accents (MySQL's default collation) treats them as one name. There the apply
    # stops on the second, says why, and writes neither. The NOTE says which happened.
    accents = ("e2e transfer Café", "e2e transfer Cafe")
    pair = b.role_file([(name, ["viewChannels"], None) for name in accents])
    plan = _preview(r, a, pair, label="a preview of two names that differ only by an accent")
    status, body = _apply(a, pair, plan, accents)
    written = [name for name in accents if name in _roles_by_name(a)]
    r.check("import: two names that differ only by an accent are both written, or refused (400) with the reason"
            " and neither written",
            (status == 200 and len(written) == 2)
            or (status == 400 and "Rename one of them in the file." in body and not written),
            f"HTTP {status}: {body[:200]}; written: {written}")
    r.note("import of two names that differ only by an accent",
           "both written" if status == 200 else f"HTTP {status}, neither written: {body[:200]}")


def _transfer_from_another_engine(r, a, db_server):
    """A file exported on an engine on Derby. Its channels have other ids here, so each matches only by name and is
    used only when the import matches channels by name. It holds "e2e Derby Lab" and "e2e Derby LAB": Derby,
    Postgres and Oracle take both; MySQL and SQL Server hold them as one name, so applying both is refused with the
    reason and writes nothing, and the rest goes in without one of them."""
    with open(FROM_DERBY, encoding="utf-8") as f:
        text = f.read()
    exported = b.parse_export(text)[1]
    file_channels = {fid: name for role in exported.values() for fid, name in role["channels"].items()}
    here = {}
    for name in sorted(set(file_channels.values())):
        cid = b.new_id()
        ok, detail = b.create_channel(a, cid, name)
        r.check(f"create channel {name} here, under a new id", ok, detail)
        here[name] = cid
    restricted = [n for n, role in exported.items() if role["restricted"]]

    plan = _preview(r, a, text, label="a preview of a file from another engine")
    r.check("import from another engine: each of the file's channels is listed as a match by name",
            {m["file_id"]: (m["name"], m["channel_id"]) for m in plan["matches"]}
            == {fid: (name, here[name]) for fid, name in file_channels.items()} and not plan["match_by_name"],
            str(plan["matches"]))
    r.check("import from another engine: without matching by name, a restricted role is skipped and says why",
            all(plan["rows"].get(n, {}).get("action") == "SKIP"
                and "Matching channels by name finds" in (plan["rows"][n].get("reason") or "")
                for n in restricted), str(plan["rows"]))

    plan = _preview(r, a, text, label="a preview matching channels by name", match_by_name=True)
    r.check("import from another engine: matching channels by name, every role is planned as new",
            {n: row["action"] for n, row in plan["rows"].items()} == {n: "CREATE" for n in exported}
            and plan["match_by_name"], str(plan["rows"]))
    names = list(exported)
    status, body = _apply(a, text, plan, names, match_by_name=True)
    if db_server in ONE_NAME_FOR_BOTH_CASES:
        r.check("import from another engine: 'e2e Derby Lab' and 'e2e Derby LAB' are one name on this database, so"
                " the apply is refused (400) with the reason and writes nothing",
                status == 400 and "Rename one of them in the file." in body
                and not any(n in _roles_by_name(a) for n in names), f"HTTP {status}: {body[:200]}")
        names.remove("e2e Derby LAB")
        status, body = _apply(a, text, plan, names, match_by_name=True)
    now = _roles_by_name(a)
    r.check("import from another engine: the roles are written, with this engine's ids for their channels",
            status == 200 and all(now.get(n, {}).get("channelIds")
                                  == {here[c] for c in exported[n]["channels"].values()} for n in names),
            f"HTTP {status}: {body[:200]}; {[now.get(n) for n in names]}")
