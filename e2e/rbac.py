# SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
# SPDX-License-Identifier: MPL-2.0

"""REST helpers for the end-to-end tests: the engine's installer, users and channels, rbac's roles and
assignments, and Data Pruner. Standard library only."""

import os
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from oie import ApiError

RBAC = "/extensions/rbac"
PLUGIN_PATH = "rbac"
PLUGIN_NAME = "Role-Based Access Control"
DATA_PRUNER = "/extensions/datapruner"


def new_id():
    return str(uuid.uuid4())


# ---------- extensions

def install(api, zip_path):
    with open(zip_path, "rb") as f:
        payload = f.read()
    status, text = api.multipart("/extensions/_install",
                                 [("file", os.path.basename(zip_path), "application/zip", payload)])
    return status in (200, 204), f"HTTP {status} {api.reason} {text[:200]}"


def uninstall(api):
    # The engine writes the body verbatim into extensions/uninstall, so it is the bare path:
    # an XML-wrapped <string> is written literally and matches no extension folder.
    status, text = api.request("POST", "/extensions/_uninstall", PLUGIN_PATH)
    return status in (200, 204), f"HTTP {status} {api.reason} {text[:200]}"


def plugin_meta(api):
    """(pluginVersion, mirthVersion) of the loaded rbac, or None when the engine hasn't loaded it."""
    root = api.xml("GET", "/extensions/plugins")
    for el in root.iter("pluginMetaData"):
        if el.get("path") == PLUGIN_PATH:
            return el.findtext("pluginVersion"), el.findtext("mirthVersion")
    return None


# ---------- engine users

def create_user(api, username, password):
    """Creates an engine user and sets its password. Returns the user's id."""
    user = ET.Element("user")
    for tag, text in (("username", username), ("firstName", "Rbac"), ("lastName", "e2e"),
                      ("email", f"{username}@example.com")):
        ET.SubElement(user, tag).text = text
    api.xml("POST", "/users", ET.tostring(user, encoding="unicode"))
    uid = api.xml("GET", f"/users/{username}").findtext("id")
    status, text = api.request("PUT", f"/users/{uid}/password", password, content_type="text/plain")
    if status not in (200, 204) or "<string>" in text:   # a list of strings is the password rules it broke
        raise ApiError(f"PUT /users/{uid}/password -> HTTP {status}: {text[:300]}")
    return uid


def visible_users(api):
    """The usernames GET /users returns to this caller."""
    status, text = api.request("GET", "/users")
    if status != 200:
        return status, None
    return status, sorted(el.findtext("username") for el in ET.fromstring(text).iter("user"))


# ---------- rbac roles and assignments

def role_xml(name, permissions=(), channel_ids=(), is_admin=False, description="rbac e2e"):
    role = ET.Element("com.diridium.rbac.Role")
    ET.SubElement(role, "name").text = name
    ET.SubElement(role, "description").text = description
    for tag, values in (("permissions", permissions), ("channelIds", channel_ids)):
        holder = ET.SubElement(role, tag)
        for value in values:
            ET.SubElement(holder, "string").text = value
    ET.SubElement(role, "isAdmin").text = "true" if is_admin else "false"
    return ET.tostring(role, encoding="unicode")


def parse_role(el):
    return {
        "id": el.findtext("id"),
        "name": el.findtext("name"),
        "description": el.findtext("description"),
        "permissions": {s.text for s in el.findall("permissions/string")},
        "channelIds": {s.text for s in el.findall("channelIds/string")},
        "isAdmin": el.findtext("isAdmin") == "true",
    }


def roles(api):
    """{role id: role} as GET /roles returns them. Raises unless the call succeeds."""
    root = api.xml("GET", RBAC + "/roles")
    return {r["id"]: r for r in (parse_role(el) for el in root.iter("com.diridium.rbac.Role"))}


def admin_role(api):
    flagged = [r for r in roles(api).values() if r["isAdmin"]]
    return flagged[0] if len(flagged) == 1 else None


def create_role(api, name, permissions=(), channel_ids=(), is_admin=False):
    """Creates a role and returns its id. Raises unless the call succeeds."""
    return api.xml("POST", RBAC + "/roles", role_xml(name, permissions, channel_ids, is_admin)).findtext("id")


def post_role(api, xml):
    status, text = api.request("POST", RBAC + "/roles", xml)
    return status, text


def put_role(api, role_id, xml):
    return api.request("PUT", f"{RBAC}/roles/{role_id}", xml)


def delete_role(api, role_id):
    return api.request("DELETE", f"{RBAC}/roles/{role_id}")


def user_role(api, user_id):
    """The user's role, or None when the user has none."""
    status, text = api.request("GET", f"{RBAC}/users/{user_id}/role")
    if status == 204 or (status == 200 and not text.strip()):
        return None
    if status != 200:
        raise ApiError(f"GET {RBAC}/users/{user_id}/role -> HTTP {status} {api.reason}: {text[:200]}")
    return parse_role(ET.fromstring(text))


def assign_role(api, user_id, role_id):
    return api.request("POST", f"{RBAC}/users/{user_id}/role/{role_id}")


def remove_role(api, user_id):
    return api.request("DELETE", f"{RBAC}/users/{user_id}/role")


def available_permissions(api):
    """Every permission a role can be given on this engine."""
    root = api.xml("GET", RBAC + "/permissions")
    return {el.text for el in root.iter("string")}


def plugin_events(api, attribute_search):
    """rbac's audit events whose attributes contain attribute_search, newest first, each as {attribute: value}."""
    status, text = api.request("GET", "/events", query={"name": PLUGIN_NAME, "attributeSearch": attribute_search})
    if status != 200:
        raise ApiError(f"GET /events -> HTTP {status} {api.reason}: {text[:200]}")
    events = []
    for el in ET.fromstring(text).iter("event"):
        pairs = [[s.text for s in entry.findall("string")] for entry in el.findall("attributes/entry")]
        events.append({pair[0]: pair[1] for pair in pairs if len(pair) == 2})
    return events


def my_permissions(api):
    status, text = api.request("GET", RBAC + "/my-permissions")
    if status != 200:
        return status, None
    return status, {el.text for el in ET.fromstring(text).iter("string")}


# ---------- role export and import

def export_roles(api, role_ids=()):
    """(status, text) of an export. The endpoint answers text/plain only; any other Accept gets HTTP 406."""
    query = {"roleId": list(role_ids)} if role_ids else None
    return api.request("GET", RBAC + "/roles/_export", query=query, accept="text/plain")


def import_roles(api, text, dry_run=True, apply_channels=True, pick=(), token=None):
    """(status, text) of an import preview (dry_run) or apply."""
    query = {"dryRun": "true" if dry_run else "false", "applyChannels": "true" if apply_channels else "false"}
    if pick:
        query["pick"] = list(pick)
    if token:
        query["planToken"] = token
    return api.request("POST", RBAC + "/roles/_import", text, content_type="text/plain", query=query)


def parse_export(text):
    """(root attributes, {role name: {permissions, restricted, channels: {id: name}}}) of an export file."""
    root = ET.fromstring(text)
    roles_by_name = {}
    for el in root.findall("role"):
        channels = el.find("channels")
        roles_by_name[el.findtext("name")] = {
            "permissions": {p.text for p in el.findall("permissions/permission")},
            "restricted": channels.get("restricted") == "true",
            "channels": {c.get("id"): c.get("name") for c in channels.findall("channel")},
        }
    return dict(root.attrib), roles_by_name


def parse_import(text):
    """An import result: importable, refusal, applied, token, and rows by name (action, reason, channels,
    dropped permissions, unmatched channels, and what an overwrite changes)."""
    root = ET.fromstring(text)
    holder = root.find("rows")
    rows = {}
    for el in (holder if holder is not None else []):
        rows[el.findtext("name")] = {
            "index": int(el.findtext("index")),
            "action": el.findtext("action"),
            "reason": el.findtext("reason"),
            "channels": el.findtext("channels"),
            "dropped": [s.text for s in el.findall("droppedPermissions/string")],
            "unmatched": [s.text for s in el.findall("unmatchedChannels/string")],
            "description_changed": el.findtext("descriptionChanged") == "true",
            "added_permissions": [s.text for s in el.findall("addedPermissions/string")],
            "removed_permissions": [s.text for s in el.findall("removedPermissions/string")],
            "added_channels": [s.text for s in el.findall("addedChannels/string")],
            "removed_channels": [s.text for s in el.findall("removedChannels/string")],
        }
    return {"importable": root.findtext("importable") == "true", "refusal": root.findtext("refusal"),
            "applied": root.findtext("applied") == "true", "token": root.findtext("planToken"), "rows": rows}


def role_file(roles, format_version="1"):
    """A role export file written here rather than by rbac. roles: (name, permissions, channels), channels a
    list of (id, name), or None for every channel."""
    def attr(value):
        return escape(value, {'"': "&quot;"})

    out = [f'<rbacRoles formatVersion="{format_version}" rbacVersion="e2e" engineVersion="e2e">']
    for name, permissions, channels in roles:
        out.append(f"<role><name>{escape(name)}</name><description>rbac e2e</description><permissions>")
        out += [f"<permission>{escape(p)}</permission>" for p in permissions]
        out.append("</permissions>")
        if channels is None:
            out.append('<channels restricted="false"/>')
        else:
            out.append('<channels restricted="true">'
                       + "".join(f'<channel id="{attr(cid)}" name="{attr(cname)}"/>' for cid, cname in channels)
                       + "</channels>")
        out.append("</role>")
    out.append("</rbacRoles>")
    return "".join(out)


# ---------- channels: never deployed; the checks only list, read and remove them

CHANNEL_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "channel.xml")


def channel_xml(cid, name):
    """The engine's own no-op test channel (fixtures/channel.xml) under a new id and name. It is saved at OIE
    4.5.2, and every engine the tests run reads it by migrating it forward."""
    channel = ET.parse(CHANNEL_FIXTURE).getroot()
    channel.find("id").text = cid
    channel.find("name").text = name
    channel.find("description").text = "rbac e2e"
    return ET.tostring(channel, encoding="unicode")


def create_channel(api, cid, name):
    # The answer is a bare boolean, which the engine renders as JSON but not as XML (HTTP 406).
    status, text = api.request("POST", "/channels", channel_xml(cid, name), accept="application/json")
    return status in (200, 201) and "true" in text, f"HTTP {status} {api.reason}: {text[:200]}"


def channel_ids(api):
    """The channel ids GET /channels returns to this caller, or (status, None) when refused."""
    status, text = api.request("GET", "/channels")
    if status != 200:
        return status, None
    return status, {el.findtext("id") for el in ET.fromstring(text).findall("channel")}


def ids_and_names(api):
    """The channel ids GET /channels/idsAndNames returns to this caller."""
    status, text = api.request("GET", "/channels/idsAndNames")
    if status != 200:
        return status, None
    return status, {entry.findall("string")[0].text for entry in ET.fromstring(text).iter("entry")}
