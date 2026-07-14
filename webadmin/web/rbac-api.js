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

/* Coerce a raw wire Role into a stable client shape (id:number|null, name/
   description:string, permissions/channelIds:Set<string>, isAdmin:boolean). */
export function normalizeRole(raw) {
    if (!raw || typeof raw !== 'object') return null;
    return {
        id: raw.id === undefined || raw.id === null || raw.id === '' ? null : Number(raw.id),
        name: raw.name === undefined || raw.name === null ? '' : String(raw.name),
        description: raw.description === undefined || raw.description === null ? '' : String(raw.description),
        permissions: stringSet(raw.permissions),
        channelIds: stringSet(raw.channelIds),
        // JSON gives a real boolean; the host's XML fallback parser gives 'true'/true.
        isAdmin: raw.isAdmin === true || raw.isAdmin === 'true'
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
    parts.push(`<isAdmin>${role.isAdmin === true}</isAdmin>`);
    return `<${ROLE_FQCN}>${parts.join('')}</${ROLE_FQCN}>`;
}

/* ---- REST client (the 11 servlet endpoints) --------------------------------- */

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
