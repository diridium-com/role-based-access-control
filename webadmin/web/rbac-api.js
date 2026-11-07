// SPDX-FileCopyrightText: Copyright 2025-2026 Diridium Technologies Inc.
// SPDX-License-Identifier: MPL-2.0

/*
 * REST bindings for the RBAC servlet at /extensions/rbac (RbacServletInterface),
 * plus normalization of the engine's XStream JSON wire shapes.
 *
 * Reads go through the host's JSON pipeline (unwrap/asList): the roles list root
 * key is the FQCN `com.diridium.rbac.Role` (Role has no @XStreamAlias), a
 * Set<String> arrives as {string:[...]}, a singleton {string:'x'}, or '' when
 * empty, and Map<String,String> arrives as {entry:[{string:[k,v]}]} with the
 * same singleton/empty quirks (tolerance copied from the host's messages view).
 *
 * Writes are hand-built XStream XML (<com.diridium.rbac.Role>...) sent via
 * api.postXml/putXml — byte-parity with what the Swing client serializes, and
 * it sidesteps the unverified Jettison JSON shapes for empty Sets and FQCN
 * request roots (host precedent: statistics.clear).
 */

const EXT = '/extensions/rbac';
const ROLE_FQCN = 'com.diridium.rbac.Role';

const enc = encodeURIComponent;

/* ---- wire-shape normalization (pure; unit-testable) ------------------------ */

// Missing/empty -> [], singleton -> [x] (XStream one-element collections arrive
// as a bare object/string).
function toArray(v) {
    if (v === null || v === undefined || v === '') return [];
    return Array.isArray(v) ? v : [v];
}

/* Set<String> after the host's unwrap: {string:[...]}, singleton {string:'x'},
   or '' (empty set). A bare array/string is tolerated for robustness. */
export function stringSet(v) {
    if (v && typeof v === 'object' && !Array.isArray(v)) v = v.string;
    return new Set(toArray(v).map(String));
}

/* Map<String,String> after unwrap: {entry:[{string:[k,v]}]} or
   {entry:{string:[k,v]}} (singleton), values occasionally split as
   {string:k, <type>:v}, or a plain object. Returns [ [key, value], ... ]. */
export function mapEntries(map) {
    if (!map || typeof map !== 'object') return [];
    if (map.entry === undefined) {
        return Object.entries(map)
            .filter(([k]) => !k.startsWith('@'))
            .map(([k, v]) => [String(k), String(v)]);
    }
    const out = [];
    for (const entry of toArray(map.entry)) {
        if (!entry || typeof entry !== 'object') continue;
        if (Array.isArray(entry.string) && Object.keys(entry).length === 1) {
            out.push([String(entry.string[0]), String(entry.string[1])]);
            continue;
        }
        const values = [];
        for (const [k, v] of Object.entries(entry)) {
            if (k.startsWith('@')) continue;
            if (Array.isArray(v)) values.push(...v); else values.push(v);
        }
        if (values.length >= 2) out.push([String(values[0]), String(values[1])]);
        else if (values.length === 1) out.push([String(values[0]), '']);
    }
    return out;
}

/* A limit of the engine's JSON, not fixed here. Its XML-to-JSON writer turns a
   string that looks like a number or a keyword into that JSON type (measured on
   OIE 4.7.0 with rbac 1.3.0): a role named "1.0" arrives as the number 1.0, "1e3"
   as 1000.0, "true" as true, "null" as null and "12345678901234567890" as an
   integer, while "007" stays a string; descriptions the same. Once parsed, most
   of these can't be turned back into the text (1.0 is 1, 1e3 is 1000, null is no
   name, the long one is rounded; only true reads "true" again), so the web shows
   such a name converted, and an Apply from the role editor sends the converted
   text back. The import preview is affected the same way, but only on
   screen: the apply re-reads the file on the server. Reading roles as XML would
   fix it; see docs/design-notes.md, 2026-11-07. */

/* Coerce a raw wire Role into a stable client shape (id:number|null, name/
   description:string, permissions/channelIds:Set<string>, restricted and
   isAdmin:boolean). Names and descriptions: see the limit above. */
export function normalizeRole(raw) {
    if (!raw || typeof raw !== 'object') return null;
    return {
        id: raw.id === undefined || raw.id === null || raw.id === '' ? null : Number(raw.id),
        name: raw.name === undefined || raw.name === null ? '' : String(raw.name),
        description: raw.description === undefined || raw.description === null ? '' : String(raw.description),
        permissions: stringSet(raw.permissions),
        channelIds: stringSet(raw.channelIds),
        // A role sent without the flag but with channel ids reads as restricted
        // (the server's rule, RoleService.impliedRestriction).
        restricted: raw.restricted === undefined || raw.restricted === null
            ? stringSet(raw.channelIds).size > 0
            : raw.restricted === true || raw.restricted === 'true',
        // JSON gives a real boolean; the host's XML fallback parser gives 'true'/true.
        isAdmin: raw.isAdmin === true || raw.isAdmin === 'true'
    };
}

/* ---- import preview/apply result ------------------------------------------- */

const RESULT_FQCN = 'com.diridium.rbac.RoleImportResult';
const ROW_FQCN = 'com.diridium.rbac.RoleImportRow';
const MATCH_FQCN = 'com.diridium.rbac.ChannelNameMatch';

// A List<String> after the host's unwrap: null when empty, {string:'x'} for one
// element, {string:[...]} for several. Order is kept (the server sorts them).
function stringList(v) {
    if (v && typeof v === 'object' && !Array.isArray(v)) v = v.string;
    return toArray(v).map(String);
}

// A List<Bean> after the host's unwrap: null when empty, {<FQCN>: bean} for one
// element, {<FQCN>: [beans]} for several.
function beanList(v, fqcn) {
    if (v && typeof v === 'object' && !Array.isArray(v) && v[fqcn] !== undefined) v = v[fqcn];
    return toArray(v).filter((x) => x && typeof x === 'object');
}

const text = (v) => (v === undefined || v === null ? '' : String(v));

const CHANNEL_FQCN = 'com.diridium.rbac.RoleImportChannel';

// name, fileName and fileId stay null when the wire has none: the tables word a
// channel differently when it has no name, or no name or id in the file.
function normalizeImportChannel(raw) {
    const orNull = (v) => (v === undefined || v === null ? null : String(v));
    return {
        id: text(raw.id),
        name: orNull(raw.name),
        fileId: orNull(raw.fileId),
        fileName: orNull(raw.fileName),
        match: text(raw.match),
        used: raw.used === true || raw.used === 'true'
    };
}

function normalizeImportRow(raw) {
    return {
        index: Number(raw.index),
        name: text(raw.name),
        action: text(raw.action),
        reason: text(raw.reason),
        droppedPermissions: stringList(raw.droppedPermissions),
        matchedChannelCount: Number(raw.matchedChannelCount) || 0,
        channels: text(raw.channels),
        // The captured wire fixtures predate this field: absent means false.
        noChannelFound: raw.noChannelFound === true || raw.noChannelFound === 'true',
        existsHere: raw.existsHere === true || raw.existsHere === 'true',
        restrictedNow: raw.restrictedNow === true || raw.restrictedNow === 'true',
        restrictedAfter: raw.restrictedAfter === true || raw.restrictedAfter === 'true',
        descriptionNow: text(raw.descriptionNow),
        descriptionAfter: text(raw.descriptionAfter),
        permissionsNow: stringList(raw.permissionsNow),
        permissionsAfter: stringList(raw.permissionsAfter),
        channelsNow: beanList(raw.channelsNow, CHANNEL_FQCN).map(normalizeImportChannel),
        channelsAfter: beanList(raw.channelsAfter, CHANNEL_FQCN).map(normalizeImportChannel)
    };
}

/* Turn a RoleImportResult (after the host's unwrap of its root key) into a plain
   shape: lists are always arrays of plain strings or plain objects, formatVersion
   and the version strings are strings, flags are booleans. This is the only
   place that knows the wire quirks (a one-element list arrives as a bare
   object or string, an empty list as null, formatVersion as a number). A role
   name or description that looks like a number or a keyword arrives converted
   and shows converted (the limit above normalizeRole). */
export function normalizeImportResult(raw) {
    if (raw && typeof raw === 'object' && raw[RESULT_FQCN] !== undefined) raw = raw[RESULT_FQCN];
    if (!raw || typeof raw !== 'object') raw = {};
    return {
        importable: raw.importable === true || raw.importable === 'true',
        refusal: text(raw.refusal),
        formatVersion: text(raw.formatVersion),
        sourceRbacVersion: text(raw.sourceRbacVersion),
        sourceEngineVersion: text(raw.sourceEngineVersion),
        applyChannels: raw.applyChannels === true || raw.applyChannels === 'true',
        matchChannelsByName: raw.matchChannelsByName === true || raw.matchChannelsByName === 'true',
        applied: raw.applied === true || raw.applied === 'true',
        planToken: text(raw.planToken),
        rows: beanList(raw.rows, ROW_FQCN).map(normalizeImportRow),
        channelNameMatches: beanList(raw.channelNameMatches, MATCH_FQCN).map((m) => ({
            name: text(m.name),
            fileChannelId: text(m.fileChannelId),
            channelId: text(m.channelId)
        }))
    };
}

/* ---- XStream XML writes ----------------------------------------------------- */

function escapeXml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function stringsXml(tag, values) {
    const items = [...values].map(v => `<string>${escapeXml(v)}</string>`).join('');
    return `<${tag}>${items}</${tag}>`;
}

/* Serialize a role the way XStream expects <com.diridium.rbac.Role>. The <id>
   element is omitted on create (the database assigns it); XStream defaults the
   interface-typed Set fields to HashSet, so no class attributes are needed. */
export function roleXml(role, { includeId = false } = {}) {
    const parts = [];
    if (includeId && role.id !== null && role.id !== undefined) {
        parts.push(`<id>${Number(role.id)}</id>`);
    }
    parts.push(`<name>${escapeXml(role.name ?? '')}</name>`);
    parts.push(`<description>${escapeXml(role.description ?? '')}</description>`);
    parts.push(stringsXml('permissions', role.permissions ?? []));
    parts.push(stringsXml('channelIds', role.channelIds ?? []));
    parts.push(`<restricted>${role.restricted === true}</restricted>`);
    parts.push(`<isAdmin>${role.isAdmin === true}</isAdmin>`);
    return `<${ROLE_FQCN}>${parts.join('')}</${ROLE_FQCN}>`;
}

/* ---- REST client (the servlet endpoints) --------------------------------- */

export function makeApi(api) {
    // Roles come back {list:{'com.diridium.rbac.Role':[...]}}; tolerate an
    // aliased 'role' root too (schi precedent for FQCN/alias drift).
    const roleList = (v) => {
        const list = api.asList(v, ROLE_FQCN);
        return list.length ? list : api.asList(v, 'role');
    };
    return {
        // Role CRUD
        getRoles: async () => roleList(await api.get(`${EXT}/roles`)).map(normalizeRole),
        getRole: async (roleId) => normalizeRole(await api.get(`${EXT}/roles/${enc(roleId)}`)),
        createRole: async (role) =>
            normalizeRole(await api.postXml(`${EXT}/roles`, roleXml(role))),
        updateRole: (roleId, role) =>
            api.putXml(`${EXT}/roles/${enc(roleId)}`, roleXml(role, { includeId: true })),
        deleteRole: (roleId) => api.del(`${EXT}/roles/${enc(roleId)}`),
        // User-role assignment (getUserRole answers 204/empty when unassigned -> null)
        getUserRole: async (userId) => normalizeRole(await api.get(`${EXT}/users/${enc(userId)}/role`)),
        assignUserRole: (userId, roleId) =>
            api.post(`${EXT}/users/${enc(userId)}/role/${enc(roleId)}`, null),
        removeUserRole: (userId) => api.del(`${EXT}/users/${enc(userId)}/role`),
        // Permission discovery
        getAvailablePermissions: async () => stringSet(await api.get(`${EXT}/permissions`)),
        getMyPermissions: async () => stringSet(await api.get(`${EXT}/my-permissions`)),
        // Export: the file as the server wrote it (text/plain), byte for byte.
        exportRoles: (roleIds) =>
            api.get(`${EXT}/roles/_export`, { roleId: [...roleIds] }, { raw: true }),
        // Import: the file as a text/plain body. dryRun previews; an apply also
        // needs pick (the rows' index values) and the preview's planToken. A
        // 409/400 comes back as an Error whose message is the server's text.
        importRoles: async (file, { dryRun, applyChannels, matchChannelsByName, pick, planToken }) =>
            normalizeImportResult(await api.post(`${EXT}/roles/_import`, file, {
                params: { dryRun, applyChannels, matchChannelsByName, pick, planToken },
                contentType: 'text/plain'
            })),
        getExtensionTaskPermissions: async () =>
            Object.fromEntries(mapEntries(await api.get(`${EXT}/task-permissions`))),
        // Permission display name -> publishing plugin name; drives the
        // per-plugin headers in the role editor. Tolerates a pre-1.1.2 server
        // (404) by degrading to {} — those permissions fall back to "Other".
        getExtensionPermissionGroups: async () => {
            try {
                return Object.fromEntries(mapEntries(await api.get(`${EXT}/permissions/extensions`)));
            } catch {
                return {};
            }
        }
    };
}
