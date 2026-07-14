// web/rbac-api.js
var EXT = "/extensions/rbac";
var ROLE_FQCN = "com.diridium.rbac.Role";
var enc = encodeURIComponent;
function toArray(v) {
  if (v === null || v === void 0 || v === "") return [];
  return Array.isArray(v) ? v : [v];
}
function stringSet(v) {
  if (v && typeof v === "object" && !Array.isArray(v)) v = v.string;
  return new Set(toArray(v).map(String));
}
function mapEntries(map) {
  if (!map || typeof map !== "object") return [];
  if (map.entry === void 0) {
    return Object.entries(map).filter(([k]) => !k.startsWith("@")).map(([k, v]) => [String(k), String(v)]);
  }
  const out = [];
  for (const entry of toArray(map.entry)) {
    if (!entry || typeof entry !== "object") continue;
    if (Array.isArray(entry.string) && Object.keys(entry).length === 1) {
      out.push([String(entry.string[0]), String(entry.string[1])]);
      continue;
    }
    const values = [];
    for (const [k, v] of Object.entries(entry)) {
      if (k.startsWith("@")) continue;
      if (Array.isArray(v)) values.push(...v);
      else values.push(v);
    }
    if (values.length >= 2) out.push([String(values[0]), String(values[1])]);
    else if (values.length === 1) out.push([String(values[0]), ""]);
  }
  return out;
}
function normalizeRole(raw) {
  if (!raw || typeof raw !== "object") return null;
  return {
    id: raw.id === void 0 || raw.id === null || raw.id === "" ? null : Number(raw.id),
    name: raw.name === void 0 || raw.name === null ? "" : String(raw.name),
    description: raw.description === void 0 || raw.description === null ? "" : String(raw.description),
    permissions: stringSet(raw.permissions),
    channelIds: stringSet(raw.channelIds),
    // JSON gives a real boolean; the host's XML fallback parser gives 'true'/true.
    isAdmin: raw.isAdmin === true || raw.isAdmin === "true"
  };
}
function escapeXml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function stringsXml(tag, values) {
  const items = [...values].map((v) => `<string>${escapeXml(v)}</string>`).join("");
  return `<${tag}>${items}</${tag}>`;
}
function roleXml(role, { includeId = false } = {}) {
  const parts = [];
  if (includeId && role.id !== null && role.id !== void 0) {
    parts.push(`<id>${Number(role.id)}</id>`);
  }
  parts.push(`<name>${escapeXml(role.name ?? "")}</name>`);
  parts.push(`<description>${escapeXml(role.description ?? "")}</description>`);
  parts.push(stringsXml("permissions", role.permissions ?? []));
  parts.push(stringsXml("channelIds", role.channelIds ?? []));
  parts.push(`<isAdmin>${role.isAdmin === true}</isAdmin>`);
  return `<${ROLE_FQCN}>${parts.join("")}</${ROLE_FQCN}>`;
}
function makeApi(api) {
  const roleList = (v) => {
    const list = api.asList(v, ROLE_FQCN);
    return list.length ? list : api.asList(v, "role");
  };
  return {
    // Role CRUD
    getRoles: async () => roleList(await api.get(`${EXT}/roles`)).map(normalizeRole),
    getRole: async (roleId) => normalizeRole(await api.get(`${EXT}/roles/${enc(roleId)}`)),
    createRole: async (role) => normalizeRole(await api.postXml(`${EXT}/roles`, roleXml(role))),
    updateRole: (roleId, role) => api.putXml(`${EXT}/roles/${enc(roleId)}`, roleXml(role, { includeId: true })),
    deleteRole: (roleId) => api.del(`${EXT}/roles/${enc(roleId)}`),
    // User-role assignment (getUserRole answers 204/empty when unassigned -> null)
    getUserRole: async (userId) => normalizeRole(await api.get(`${EXT}/users/${enc(userId)}/role`)),
    assignUserRole: (userId, roleId) => api.post(`${EXT}/users/${enc(userId)}/role/${enc(roleId)}`, null),
    removeUserRole: (userId) => api.del(`${EXT}/users/${enc(userId)}/role`),
    // Permission discovery
    getAvailablePermissions: async () => stringSet(await api.get(`${EXT}/permissions`)),
    getMyPermissions: async () => stringSet(await api.get(`${EXT}/my-permissions`)),
    getExtensionTaskPermissions: async () => Object.fromEntries(mapEntries(await api.get(`${EXT}/task-permissions`))),
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

// web/task-permission-map.js
var TASK_PERMISSIONS = {
  // ========== View Navigation ==========
  doShowDashboard: "viewDashboard",
  doShowChannel: "viewChannels",
  doShowUsers: "manageUsers",
  // doShowSettings intentionally unmapped - always shown; individual tabs gated below
  doShowAlerts: "viewAlerts",
  doShowEvents: "viewEvents",
  doShowExtensions: "manageExtensions",
  // ========== Dashboard ==========
  doRefreshStatuses: "viewDashboard",
  // doFilter has no tagged control in the web administrator today (RBAC.md's
  // dashboard group does not list it) — kept anyway for 1:1 Swing parity, so
  // the JSON parity artifact equals the Swing map and a future tagged filter
  // control hides correctly.
  doFilter: "viewDashboard",
  doSendMessage: "processMessages",
  // shared task name: dashboard + message groups
  doShowMessages: "viewMessages",
  doRemoveAllMessages: "removeAllMessages",
  // shared task name: dashboard + message groups
  doClearStats: "clearStatistics",
  doStart: "startStopChannels",
  doPause: "startStopChannels",
  doStop: "startStopChannels",
  doHalt: "startStopChannels",
  doUndeployChannel: "deployUndeployChannels",
  doStartConnector: "startStopChannels",
  doStopConnector: "startStopChannels",
  // ========== Channels ==========
  doRefreshChannels: "viewChannels",
  doRedeployAll: "deployUndeployChannels",
  doDeployChannel: "deployUndeployChannels",
  doDeployInDebug: "deployUndeployChannels",
  doEditGlobalScripts: "viewGlobalScripts",
  doEditCodeTemplates: "viewCodeTemplates",
  doNewChannel: "manageChannels",
  doImportChannel: "manageChannels",
  doExportAllChannels: "viewChannels",
  doExportChannel: "viewChannels",
  // shared task name: channel + channelEdit groups
  doDeleteChannel: "manageChannels",
  doCloneChannel: "manageChannels",
  doEditChannel: "manageChannels",
  doEnableChannel: "manageChannels",
  doDisableChannel: "manageChannels",
  doViewMessages: "viewMessages",
  // ========== Channel Edit ==========
  doSaveChannel: "manageChannels",
  doValidate: "manageChannels",
  doNewDestination: "manageChannels",
  doDeleteDestination: "manageChannels",
  doCloneDestination: "manageChannels",
  doEnableDestination: "manageChannels",
  doDisableDestination: "manageChannels",
  doMoveDestinationUp: "manageChannels",
  doMoveDestinationDown: "manageChannels",
  doEditFilter: "manageChannels",
  doEditTransformer: "manageChannels",
  doEditResponseTransformer: "manageChannels",
  doImportConnector: "manageChannels",
  doExportConnector: "viewChannels",
  doValidateChannelScripts: "manageChannels",
  doDeployFromChannelView: "deployUndeployChannels",
  doDebugDeployFromChannelView: "deployUndeployChannels",
  // ========== Channel Groups ==========
  // Engine gates updateChannelGroups (which covers create/update/delete) on
  // Permissions.CHANNELS_MANAGE — only the read/export paths use viewChannelGroups.
  doSaveGroups: "manageChannels",
  doNewGroup: "manageChannels",
  doAssignChannelToGroup: "manageChannels",
  doEditGroupDetails: "manageChannels",
  doImportGroup: "manageChannels",
  doDeleteGroup: "manageChannels",
  doExportAllGroups: "viewChannelGroups",
  doExportGroup: "viewChannelGroups",
  // ========== Messages ==========
  doRefreshMessages: "viewMessages",
  doImportMessages: "importMessages",
  // doExportMessages / doExportAttachment are deliberately gated on the stronger
  // exportMessagesServer permission even though the export dialogs also offer a
  // purely local (client-side) export whose REST calls only need viewMessages.
  // Hiding both buttons from a viewMessages-only role over-restricts the local
  // path, but that is the PHI-conservative (fail-safe) direction and not a
  // security hole, so it is kept.
  doExportMessages: "exportMessagesServer",
  // Bulk-by-filter operations use a different engine permission than the
  // single-message variants. Engine: removeMessages (filtered) is gated on
  // MESSAGES_REMOVE_RESULTS; reprocessMessages (filtered) on MESSAGES_REPROCESS_RESULTS.
  doRemoveFilteredMessages: "removeResults",
  doRemoveMessage: "removeMessages",
  doReprocessFilteredMessages: "reprocessResults",
  doReprocessMessage: "reprocessMessages",
  viewImage: "viewMessages",
  doExportAttachment: "exportMessagesServer",
  // ========== Alerts ==========
  doRefreshAlerts: "viewAlerts",
  doNewAlert: "manageAlerts",
  doImportAlert: "manageAlerts",
  doExportAlerts: "viewAlerts",
  doExportAlert: "viewAlerts",
  // shared task name: alert + alertEdit groups
  doDeleteAlert: "manageAlerts",
  doEditAlert: "manageAlerts",
  doEnableAlert: "manageAlerts",
  doDisableAlert: "manageAlerts",
  // ========== Alert Edit ==========
  doSaveAlerts: "manageAlerts",
  // ========== Users ==========
  doRefreshUser: "manageUsers",
  doNewUser: "manageUsers",
  doEditUser: "manageUsers",
  doDeleteUser: "manageUsers",
  // ========== Events ==========
  doRefreshEvents: "viewEvents",
  doExportAllEvents: "viewEvents",
  // ========== Code Templates ==========
  doRefreshCodeTemplates: "viewCodeTemplates",
  doSaveCodeTemplates: "manageCodeTemplates",
  doNewCodeTemplate: "manageCodeTemplates",
  doNewLibrary: "manageCodeTemplates",
  doImportCodeTemplates: "manageCodeTemplates",
  doImportLibraries: "manageCodeTemplates",
  doExportCodeTemplate: "viewCodeTemplates",
  doExportLibrary: "viewCodeTemplates",
  doExportAllLibraries: "viewCodeTemplates",
  doDeleteCodeTemplate: "manageCodeTemplates",
  doDeleteLibrary: "manageCodeTemplates",
  doValidateCodeTemplate: "viewCodeTemplates",
  // ========== Global Scripts ==========
  doSaveGlobalScripts: "editGlobalScripts",
  doValidateCurrentGlobalScript: "viewGlobalScripts",
  doImportGlobalScripts: "editGlobalScripts",
  doExportGlobalScripts: "viewGlobalScripts",
  // ========== Extensions ==========
  doRefreshExtensions: "manageExtensions",
  doEnableExtension: "manageExtensions",
  doDisableExtension: "manageExtensions",
  doShowExtensionProperties: "manageExtensions",
  doUninstallExtension: "manageExtensions"
};
var GROUP_TASK_PERMISSIONS = {
  // ========== Settings Panels (group-specific for shared doRefresh/doSave) ==========
  // Server Settings
  "settings_Server/doRefresh": "viewServerSettings",
  "settings_Server/doSave": "editServerSettings",
  "settings_Server/doBackup": "backupServerConfiguration",
  "settings_Server/doRestore": "restoreServerConfiguration",
  "settings_Server/doClearAllStats": "clearLifetimeStats",
  // Tags
  "settings_Tags/doRefresh": "viewTags",
  "settings_Tags/doSave": "manageTags",
  // Configuration Map (the in-panel Add Row button rides doSave — RBAC.md §3)
  "settings_Configuration Map/doRefresh": "viewConfigurationMap",
  "settings_Configuration Map/doSave": "editConfigurationMap",
  "settings_Configuration Map/doImportMap": "editConfigurationMap",
  "settings_Configuration Map/doExportMap": "viewConfigurationMap",
  // Database Tasks
  "settings_Database Tasks/doRefresh": "viewDatabaseTasks",
  "settings_Database Tasks/doSave": "manageDatabaseTasks",
  "settings_Database Tasks/doRunDatabaseTask": "manageDatabaseTasks",
  "settings_Database Tasks/doCancelDatabaseTask": "manageDatabaseTasks",
  // Resources
  "settings_Resources/doRefresh": "viewResources",
  "settings_Resources/doSave": "editResources",
  "settings_Resources/doAddResource": "editResources",
  "settings_Resources/doRemoveResource": "editResources",
  "settings_Resources/doReloadResource": "reloadResources",
  // RBAC plugin settings panel (RbacServletInterface.PLUGIN_NAME /
  // PERMISSION_VIEW / PERMISSION_MANAGE)
  "settings_Role-Based Access Control/doRefresh": "View Roles",
  "settings_Role-Based Access Control/doSave": "Manage Roles"
};
var RELOAD_BACKOFF_MS = 15e3;
function mergeExtensionTaskPermissions(extensionTaskPerms) {
  if (extensionTaskPerms == null) return;
  for (const [taskName, permission] of Object.entries(extensionTaskPerms)) {
    if (!taskName || typeof permission !== "string" || !permission) continue;
    if (taskName === "__proto__") continue;
    const map = taskName.includes("/") ? GROUP_TASK_PERMISSIONS : TASK_PERMISSIONS;
    if (!Object.hasOwn(map, taskName)) {
      map[taskName] = permission;
    }
  }
}
function createController({ getPermissions, reload }) {
  let lastReloadAttemptMs = 0;
  return {
    checkTask(taskGroup, taskName) {
      const permissions = getPermissions();
      if (permissions == null) {
        const now = Date.now();
        if (typeof reload === "function" && now - lastReloadAttemptMs > RELOAD_BACKOFF_MS) {
          lastReloadAttemptMs = now;
          Promise.resolve().then(reload).catch(() => {
          });
        }
        return false;
      }
      const composite = `${taskGroup}/${taskName}`;
      let required;
      if (Object.hasOwn(GROUP_TASK_PERMISSIONS, composite)) {
        required = GROUP_TASK_PERMISSIONS[composite];
      } else if (Object.hasOwn(TASK_PERMISSIONS, taskName)) {
        required = TASK_PERMISSIONS[taskName];
      }
      if (required == null) {
        return true;
      }
      return typeof permissions.has === "function" ? permissions.has(required) : permissions.includes(required);
    }
  };
}

// web/rbac-core.js
var PERMISSION_GROUPS = {
  "Channels": [
    "viewChannels",
    "viewChannelGroups",
    "manageChannels",
    "clearStatistics",
    "startStopChannels",
    "deployUndeployChannels"
  ],
  "Messages": [
    "viewMessages",
    "removeMessages",
    "removeResults",
    "removeAllMessages",
    "processMessages",
    "reprocessMessages",
    "reprocessResults",
    "importMessages",
    "exportMessagesServer"
  ],
  "Dashboard": ["viewDashboard"],
  "Alerts": ["viewAlerts", "manageAlerts"],
  "Code Templates": ["viewCodeTemplates", "manageCodeTemplates"],
  "Global Scripts": ["viewGlobalScripts", "editGlobalScripts"],
  "Tags": ["viewTags", "manageTags"],
  "Events": ["viewEvents", "removeEvents"],
  "Users": ["manageUsers"],
  "Extensions": ["manageExtensions"],
  "Server Settings": [
    "viewServerSettings",
    "editServerSettings",
    "backupServerConfiguration",
    "restoreServerConfiguration",
    "clearLifetimeStats",
    "sendTestEmail"
  ],
  "Configuration Map": ["viewConfigurationMap", "editConfigurationMap"],
  "Database": [
    "editDatabaseDrivers",
    "viewDatabaseTasks",
    "manageDatabaseTasks"
  ],
  "Resources": ["viewResources", "editResources", "reloadResources"]
};
var BASE_PERMISSIONS = [
  "viewDashboard",
  "viewChannels",
  "viewChannelGroups",
  "viewTags"
];
var READ_ONLY_PERMISSIONS = [
  "viewDashboard",
  "viewChannels",
  "viewChannelGroups",
  "viewTags",
  "viewMessages",
  "viewAlerts",
  "viewCodeTemplates",
  "viewGlobalScripts",
  "viewEvents",
  "viewServerSettings",
  "viewConfigurationMap",
  "viewDatabaseTasks",
  "viewResources"
];
function toArray2(v) {
  if (v == null) return [];
  if (Array.isArray(v)) return v;
  if (v instanceof Set) return [...v];
  return [v];
}
function toSet(v) {
  return v instanceof Set ? v : new Set(toArray2(v));
}
function lookupName(map, id) {
  if (map == null) return void 0;
  if (map instanceof Map) return map.get(id);
  return Object.prototype.hasOwnProperty.call(map, id) ? map[id] : void 0;
}
function groupPermissions(catalog, extensionGroups) {
  const all = toSet(catalog);
  const ext = extensionGroups || {};
  const categorized = /* @__PURE__ */ new Set();
  const groups = [];
  for (const [name, members] of Object.entries(PERMISSION_GROUPS)) {
    const present = members.filter((perm) => all.has(perm));
    present.forEach((perm) => categorized.add(perm));
    if (present.length > 0) {
      groups.push({ name, permissions: present });
    }
  }
  const uncategorized = [...all].filter((perm) => !categorized.has(perm)).sort();
  const byPlugin = /* @__PURE__ */ new Map();
  const other = [];
  for (const perm of uncategorized) {
    const plugin = Object.prototype.hasOwnProperty.call(ext, perm) ? ext[perm] : null;
    if (plugin) {
      if (!byPlugin.has(plugin)) byPlugin.set(plugin, []);
      byPlugin.get(plugin).push(perm);
    } else {
      other.push(perm);
    }
  }
  for (const plugin of [...byPlugin.keys()].sort()) {
    groups.push({ name: plugin, permissions: byPlugin.get(plugin) });
  }
  if (other.length > 0) {
    groups.push({ name: "Other", permissions: other });
  }
  return groups;
}
function orphanPermissionsOf(role, catalog) {
  const all = toSet(catalog);
  return toArray2(role && role.permissions).filter((perm) => !all.has(perm)).sort();
}
function orphanChannelIdsOf(role, liveChannelIds) {
  const live = toSet(liveChannelIds);
  return toArray2(role && role.channelIds).filter((id) => !live.has(id));
}
function missingBase(selected) {
  const sel = toSet(selected);
  return BASE_PERMISSIONS.filter((perm) => !sel.has(perm));
}
function buildAssignmentPreview(username, currentRoleName, role, channelIdToName) {
  let details = "";
  details += "User:         " + username + "\n";
  details += "Current role: " + (currentRoleName != null ? currentRoleName : "(none)") + "\n";
  details += "New role:     " + role.name + "\n\n";
  const channelIds = toArray2(role.channelIds);
  if (channelIds.length === 0) {
    details += "Channel access: All channels\n\n";
  } else {
    details += "Channel access: restricted to " + channelIds.length + " channel(s):\n";
    const channelLabels = channelIds.map((id) => {
      const name = lookupName(channelIdToName, id);
      return name != null ? "  " + name : "  " + id + " (deleted)";
    });
    channelLabels.sort();
    for (const label of channelLabels) {
      details += label + "\n";
    }
    details += "\n";
  }
  const sortedPerms = toArray2(role.permissions).slice().sort();
  details += "Permissions (" + sortedPerms.length + "):\n";
  if (sortedPerms.length === 0) {
    details += "  (none \u2014 the user could log in but perform no actions)\n";
  } else {
    for (const perm of sortedPerms) {
      details += "  " + perm + "\n";
    }
  }
  return details;
}
var MANAGE_EXTENSIONS_WARNING = "Manage Extensions grants full control over installed plugins,\nincluding disabling RBAC itself. A user with this permission can\neffectively remove all access control after a server restart.\nGrant only to fully trusted administrators.";
var READ_ONLY_TOOLTIP = "Select all view-only permissions (minimum for a functional read-only user)";
var TITLE_ADD_ROLE = "Add Role";
var TITLE_EDIT_ROLE = "Edit Role";
var MSG_NAME_REQUIRED = "Role name is required.";
var TITLE_VALIDATION_ERROR = "Validation Error";
var MSG_CATALOG_EMPTY_EDIT = "The permission list did not load, so this role cannot be edited safely.\nClose this dialog, click Refresh, and try again.";
var TITLE_PERMISSIONS_UNAVAILABLE = "Permissions Unavailable";
function missingBaseWarningText(missing) {
  return "This role is missing base permissions needed for login:\n[" + toArray2(missing).join(", ") + "]\n\nUsers with this role may not be able to use the UI.\nApply anyway?";
}
var TITLE_MISSING_BASE_PERMISSIONS = "Missing Base Permissions";
var MSG_EMPTY_WHITELIST_FLIP = "This role will no longer be restricted to specific channels.\nUsers with this role will be able to access ALL channels.\n\nContinue?";
var TITLE_NO_CHANNEL_RESTRICTIONS = "No Channel Restrictions";
var ORPHAN_CHANNELS_TITLE = "Deleted channels (no longer exist)";
var ORPHAN_CHANNELS_HINT = "Still referenced by this role. Check Purge to remove a reference on Apply.";
function orphanChannelRowLabel(id) {
  return id + "  (deleted)";
}
var IMMEDIATE_NOTICE = "Changes on this tab are applied to the server immediately when you confirm each action. The Save button does not stage changes here.";
var ROLE_COLUMNS = ["ID", "Name", "Description"];
var USER_COLUMNS = ["User ID", "Username", "Assigned Role"];
var NONE_ROLE_LABEL = "(none)";
var MSG_CATALOG_NOT_LOADED = "The permission list has not finished loading. Click Refresh and try again.";
var MSG_SELECT_ROLE_EDIT = "Please select a role to edit.";
var MSG_SELECT_ROLE_DELETE = "Please select a role to delete.";
var MSG_SELECT_USER_ASSIGN = "Please select a user to assign a role to.";
var MSG_SELECT_USER_REMOVE = "Please select a user to remove their role.";
var MSG_ADMIN_ROLE_CANNOT_DELETE = "The admin role cannot be deleted.";
function deleteRoleConfirmText(roleName) {
  return 'Are you sure you want to delete role "' + roleName + '"?\nUsers with this role will lose all access.\n\nThis change takes effect immediately.';
}
var TITLE_CONFIRM_DELETE = "Confirm Delete";
function removeRoleConfirmText(username) {
  return 'Remove the role from user "' + username + '"?\nThey will lose all access.\n\nThis change takes effect immediately.';
}
var TITLE_CONFIRM_REMOVE = "Confirm Remove";
var MSG_NO_ROLES = "No roles available. Create a role first.";
function assignRolePromptText(username) {
  return "Select a role for user " + username + ":";
}
var TITLE_ASSIGN_ROLE = "Assign Role";
var ASSIGN_PREVIEW_HEADER = "Review the access this role grants before assigning:";
var ASSIGN_PREVIEW_FOOTER = "This assignment takes effect immediately.";
var TITLE_CONFIRM_ASSIGNMENT = "Confirm Role Assignment";

// web/role-editor.jsx
var EDITOR_CSS = `
.rbac-overlay {
    position: fixed;
    top: 0; right: 0; bottom: 0; left: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.45);
    /* Below the host's .modal-overlay (100): the Apply confirms and validation
       alerts (ui.modal / ui.confirmDialog) must stack above this editor. */
    z-index: 95;
}
.rbac-editor {
    width: 720px;
    max-width: 92vw;
    height: 600px;
    max-height: 88vh;
    display: flex;
    flex-direction: column;
}
.rbac-editor > .panel-body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    display: flex;
    flex-direction: column;
}
.rbac-form-row { flex: none; display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.rbac-form-row > label { flex: none; width: 90px; margin: 0; }
.rbac-form-row > input { flex: 1; }
/* flex:none \u2014 the panel-body is a height-constrained flex column and the host's
   .tabs has overflow-y:hidden, so without it the overflowing permission grid
   squashes the tab strip to zero height (tabs invisible + unclickable). */
.rbac-editor .tabs { flex: none; margin: 4px 0 10px; }
.rbac-preset-row { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.rbac-perm-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; align-items: start; }
.rbac-fieldset { border: 1px solid var(--line, #8884); border-radius: 4px; padding: 4px 10px 8px; margin: 0; min-width: 0; }
.rbac-fieldset legend { font-size: 11px; font-weight: 600; padding: 0 4px; }
.rbac-check { display: flex; align-items: center; gap: 6px; font-size: 12px; margin: 3px 0; cursor: pointer; }
.rbac-check input { margin: 0; flex: none; }
.rbac-orphan-label { font-family: monospace; font-size: 11px; }
.rbac-channel-list {
    display: flex;
    flex-direction: column;
    margin-top: 8px;
    border: 1px solid var(--line, #8884);
    border-radius: 4px;
}
.rbac-channel-list .rbac-check {
    margin: 0;
    padding: 7px 10px;
    border-bottom: 1px solid color-mix(in srgb, var(--line, #888) 45%, transparent);
}
.rbac-channel-list .rbac-check:last-child { border-bottom: 0; }
.rbac-channel-list .rbac-check:hover { background: color-mix(in srgb, var(--accent, #46f) 7%, transparent); }
.rbac-channel-list .rbac-check:has(input:disabled) { opacity: 0.55; cursor: default; }
.rbac-ch-id { font-family: monospace; font-size: 11px; color: var(--text-dim, #888); }
.rbac-editor-foot {
    flex: none;
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 10px 14px;
    border-top: 1px solid var(--line, #8884);
}
`;
function makeRoleEditor(platform) {
  const React = platform.React;
  const ui = platform.ui;
  function alertDialog(title, message) {
    return new Promise((resolve) => {
      ui.modal({
        title,
        body: ui.h("div", { style: "white-space: pre-line" }, message),
        onClose: () => resolve(),
        buttons: [{ label: "OK", primary: true, onClick: () => resolve() }]
      });
    });
  }
  function confirmYesNo(title, message) {
    return new Promise((resolve) => {
      ui.modal({
        title,
        body: ui.h("div", { style: "white-space: pre-line" }, message),
        onClose: () => resolve(false),
        buttons: [
          { label: "No", onClick: () => resolve(false) },
          { label: "Yes", primary: true, onClick: () => resolve(true) }
        ]
      });
    });
  }
  function RoleEditor({ role, catalog, extGroups, channels, onApply, onCancel }) {
    const isAdmin = !!(role && role.isAdmin);
    const catalogEmpty = !catalog || catalog.size === 0;
    const groups = React.useMemo(() => groupPermissions(catalog || [], extGroups), [catalog, extGroups]);
    const liveIds = React.useMemo(() => new Set(channels.map((c) => c.id)), [channels]);
    const orphanPerms = React.useMemo(() => orphanPermissionsOf(role, catalog || []), [role, catalog]);
    const orphanChannels = React.useMemo(() => orphanChannelIdsOf(role, liveIds), [role, liveIds]);
    const [name, setName] = React.useState(role ? role.name : "");
    const [description, setDescription] = React.useState(role ? role.description : "");
    const [selected, setSelected] = React.useState(() => new Set(
      role ? [...role.permissions].filter((p) => catalog && catalog.has(p)) : []
    ));
    const [mode, setMode] = React.useState(
      role && role.channelIds.size > 0 ? "specific" : "all"
    );
    const [checkedChannels, setCheckedChannels] = React.useState(() => new Set(
      role ? [...role.channelIds].filter((id) => liveIds.has(id)) : []
    ));
    const [purged, setPurged] = React.useState(() => /* @__PURE__ */ new Set());
    const [tab, setTab] = React.useState("permissions");
    const channelsEnabled = mode === "specific" && !isAdmin;
    React.useEffect(() => {
      const onKey = (e) => {
        if (e.key === "Escape" && !document.querySelector(".modal-overlay")) onCancel();
      };
      document.addEventListener("keydown", onKey);
      return () => document.removeEventListener("keydown", onKey);
    }, [onCancel]);
    const toggleIn = (set, value) => {
      const next = new Set(set);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    };
    async function apply() {
      const trimmedName = name.trim();
      if (!trimmedName) {
        await alertDialog(TITLE_VALIDATION_ERROR, MSG_NAME_REQUIRED);
        return;
      }
      if (catalogEmpty && role) {
        await alertDialog(TITLE_PERMISSIONS_UNAVAILABLE, MSG_CATALOG_EMPTY_EDIT);
        return;
      }
      const selectedPerms = new Set(selected);
      for (const perm of orphanPerms) selectedPerms.add(perm);
      const missing = missingBase(selectedPerms);
      if (missing.length > 0) {
        if (!await confirmYesNo(TITLE_MISSING_BASE_PERMISSIONS, missingBaseWarningText(missing))) {
          return;
        }
      }
      const selectedChannels = /* @__PURE__ */ new Set();
      if (mode === "specific") {
        for (const id of checkedChannels) selectedChannels.add(id);
        for (const id of orphanChannels) {
          if (!purged.has(id)) selectedChannels.add(id);
        }
        if (selectedChannels.size === 0) {
          if (!await confirmYesNo(TITLE_NO_CHANNEL_RESTRICTIONS, MSG_EMPTY_WHITELIST_FLIP)) {
            return;
          }
        }
      }
      onApply({
        id: role ? role.id : null,
        name: trimmedName,
        description: description.trim(),
        // Admin role: permission/channel controls are locked, so re-send
        // the stored values unchanged — only the description can differ.
        permissions: isAdmin ? new Set(role.permissions) : selectedPerms,
        channelIds: isAdmin ? new Set(role.channelIds) : selectedChannels
      });
    }
    return /* @__PURE__ */ React.createElement("div", { className: "rbac-overlay" }, /* @__PURE__ */ React.createElement("style", null, EDITOR_CSS), /* @__PURE__ */ React.createElement("div", { className: "panel rbac-editor" }, /* @__PURE__ */ React.createElement("div", { className: "panel-header" }, role ? TITLE_EDIT_ROLE : TITLE_ADD_ROLE), /* @__PURE__ */ React.createElement("div", { className: "panel-body" }, /* @__PURE__ */ React.createElement("div", { className: "rbac-form-row" }, /* @__PURE__ */ React.createElement("label", null, "Name:"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        value: name,
        disabled: isAdmin,
        onChange: (e) => setName(e.target.value)
      }
    )), /* @__PURE__ */ React.createElement("div", { className: "rbac-form-row" }, /* @__PURE__ */ React.createElement("label", null, "Description:"), /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "text",
        value: description,
        onChange: (e) => setDescription(e.target.value)
      }
    )), /* @__PURE__ */ React.createElement("div", { className: "tabs" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        className: "tab" + (tab === "permissions" ? " active" : ""),
        onClick: () => setTab("permissions")
      },
      "Permissions"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        className: "tab" + (tab === "channels" ? " active" : ""),
        onClick: () => setTab("channels")
      },
      "Channel Restrictions"
    )), tab === "permissions" ? /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "rbac-preset-row" }, /* @__PURE__ */ React.createElement(
      "button",
      {
        className: "btn",
        disabled: isAdmin,
        onClick: () => setSelected(new Set(catalog || []))
      },
      "Select All"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        className: "btn",
        disabled: isAdmin,
        onClick: () => setSelected(/* @__PURE__ */ new Set())
      },
      "Deselect All"
    ), /* @__PURE__ */ React.createElement(
      "button",
      {
        className: "btn",
        disabled: isAdmin,
        title: READ_ONLY_TOOLTIP,
        onClick: () => setSelected(new Set(
          READ_ONLY_PERMISSIONS.filter((p) => catalog && catalog.has(p))
        ))
      },
      "Read-Only"
    )), /* @__PURE__ */ React.createElement("div", { className: "rbac-perm-grid" }, groups.map((group) => /* @__PURE__ */ React.createElement("fieldset", { key: group.name, className: "rbac-fieldset" }, /* @__PURE__ */ React.createElement("legend", null, group.name), group.permissions.map((perm) => /* @__PURE__ */ React.createElement(
      "label",
      {
        key: perm,
        className: "rbac-check",
        title: perm === "manageExtensions" ? MANAGE_EXTENSIONS_WARNING : null
      },
      /* @__PURE__ */ React.createElement(
        "input",
        {
          type: "checkbox",
          checked: selected.has(perm),
          disabled: isAdmin,
          onChange: () => setSelected((s) => toggleIn(s, perm))
        }
      ),
      perm
    )))))) : /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "rbac-preset-row" }, /* @__PURE__ */ React.createElement("label", { className: "rbac-check" }, /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "radio",
        name: "rbac-channel-mode",
        checked: mode === "all",
        disabled: isAdmin,
        onChange: () => setMode("all")
      }
    ), "All Channels"), /* @__PURE__ */ React.createElement("label", { className: "rbac-check" }, /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "radio",
        name: "rbac-channel-mode",
        checked: mode === "specific",
        disabled: isAdmin,
        onChange: () => setMode("specific")
      }
    ), "Specific Channels")), orphanChannels.length > 0 ? /* @__PURE__ */ React.createElement("fieldset", { className: "rbac-fieldset" }, /* @__PURE__ */ React.createElement("legend", null, ORPHAN_CHANNELS_TITLE), /* @__PURE__ */ React.createElement("div", { className: "hint" }, ORPHAN_CHANNELS_HINT), orphanChannels.map((id) => /* @__PURE__ */ React.createElement("label", { key: id, className: "rbac-check" }, /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "checkbox",
        checked: purged.has(id),
        disabled: !channelsEnabled,
        onChange: () => setPurged((s) => toggleIn(s, id))
      }
    ), "Purge", /* @__PURE__ */ React.createElement("span", { className: "rbac-orphan-label" }, orphanChannelRowLabel(id))))) : null, /* @__PURE__ */ React.createElement("div", { className: "rbac-channel-list" }, channels.map((channel) => /* @__PURE__ */ React.createElement("label", { key: channel.id, className: "rbac-check" }, /* @__PURE__ */ React.createElement(
      "input",
      {
        type: "checkbox",
        checked: checkedChannels.has(channel.id),
        disabled: !channelsEnabled,
        onChange: () => setCheckedChannels((s) => toggleIn(s, channel.id))
      }
    ), /* @__PURE__ */ React.createElement("span", null, channel.name), /* @__PURE__ */ React.createElement("span", { className: "rbac-ch-id" }, channel.id))), channels.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: "hint" }, "No channels") : null))), /* @__PURE__ */ React.createElement("div", { className: "rbac-editor-foot" }, /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: onCancel }, "Cancel"), /* @__PURE__ */ React.createElement("button", { className: "btn btn-primary", onClick: () => apply() }, "Apply"))));
  }
  return RoleEditor;
}

// web/roles-panel.jsx
var RBAC_GROUP = "settings_Role-Based Access Control";
function registerRolesPanel(platform, api) {
  const React = platform.React;
  const ui = platform.ui;
  const RoleEditor = makeRoleEditor(platform);
  function pickRole(roles, username) {
    return new Promise((resolve) => {
      const sel = ui.select(
        roles.map((r) => ({ value: r.id, label: r.name })),
        roles[0].id
      );
      ui.modal({
        title: TITLE_ASSIGN_ROLE,
        body: ui.field(assignRolePromptText(username), sel),
        onClose: () => resolve(null),
        buttons: [
          { label: "Cancel", onClick: () => resolve(null) },
          { label: "OK", primary: true, onClick: () => resolve(sel.value) }
        ]
      });
    });
  }
  function confirmAssignment(username, currentRoleName, role, channelMap) {
    const preview = buildAssignmentPreview(username, currentRoleName, role, channelMap);
    return new Promise((resolve) => {
      ui.modal({
        title: TITLE_CONFIRM_ASSIGNMENT,
        body: ui.h(
          "div",
          ui.h("div", { style: "margin-bottom: 8px" }, ASSIGN_PREVIEW_HEADER),
          ui.h("pre", {
            style: "margin: 0; max-height: 260px; overflow: auto; font-size: 12px; border: 1px solid var(--line, #8884); border-radius: 4px; padding: 8px 10px;"
          }, preview),
          ui.h("div", { style: "margin-top: 8px; font-style: italic" }, ASSIGN_PREVIEW_FOOTER)
        ),
        onClose: () => resolve(false),
        buttons: [
          { label: "Cancel", onClick: () => resolve(false) },
          { label: "OK", primary: true, onClick: () => resolve(true) }
        ]
      });
    });
  }
  function RolesPanel({ setTasks }) {
    const [roles, setRoles] = React.useState([]);
    const [users, setUsers] = React.useState([]);
    const [usersError, setUsersError] = React.useState(null);
    const [userRoles, setUserRoles] = React.useState({});
    const [catalog, setCatalog] = React.useState(null);
    const [extGroups, setExtGroups] = React.useState({});
    const [channels, setChannels] = React.useState([]);
    const [selectedRoleId, setSelectedRoleId] = React.useState(null);
    const [selectedUserId, setSelectedUserId] = React.useState(null);
    const [editor, setEditor] = React.useState(null);
    const [loading, setLoading] = React.useState(true);
    const loadingRef = React.useRef(false);
    const pendingRef = React.useRef(false);
    const load = React.useCallback(async () => {
      if (loadingRef.current) {
        pendingRef.current = true;
        return;
      }
      loadingRef.current = true;
      setLoading(true);
      try {
        const [rolesRes, permsRes, extGroupsRes, channelsRes, usersRes] = await Promise.allSettled([
          api.getRoles(),
          api.getAvailablePermissions(),
          api.getExtensionPermissionGroups(),
          platform.api.channels.idsAndNames(),
          platform.api.users.list()
        ]);
        if (rolesRes.status === "fulfilled") setRoles(rolesRes.value);
        else ui.toast(`Failed to load roles: ${rolesRes.reason && rolesRes.reason.message || rolesRes.reason}`, "error");
        if (permsRes.status === "fulfilled") setCatalog(permsRes.value);
        if (extGroupsRes.status === "fulfilled") setExtGroups(extGroupsRes.value);
        if (channelsRes.status === "fulfilled") {
          setChannels(mapEntries(channelsRes.value).map(([id, name]) => ({ id, name })));
        }
        if (usersRes.status === "fulfilled") {
          const list = usersRes.value;
          const names = {};
          await Promise.all(list.map(async (u) => {
            try {
              const role = await api.getUserRole(u.id);
              names[u.id] = role ? role.name : null;
            } catch {
              names[u.id] = null;
            }
          }));
          setUsers(list);
          setUserRoles(names);
          setUsersError(null);
        } else {
          setUsers([]);
          setUserRoles({});
          setUsersError(String(usersRes.reason && usersRes.reason.message || usersRes.reason));
        }
      } finally {
        loadingRef.current = false;
        setLoading(false);
        if (pendingRef.current) {
          pendingRef.current = false;
          load();
        }
      }
    }, []);
    React.useEffect(() => {
      load();
      setTasks("Role-Based Access Control Tasks", [
        ui.taskButton("Refresh", "refresh", () => load(), { task: "doRefresh", group: RBAC_GROUP })
      ]);
    }, [load, setTasks]);
    const canManage = platform.checkTask(RBAC_GROUP, "doSave");
    const channelMap = React.useMemo(
      () => new Map(channels.map((c) => [c.id, c.name])),
      [channels]
    );
    const selectedRole = roles.find((r) => String(r.id) === String(selectedRoleId)) || null;
    const selectedUser = users.find((u) => String(u.id) === String(selectedUserId)) || null;
    const catalogNotLoaded = () => {
      if (!catalog || catalog.size === 0) {
        ui.toast(MSG_CATALOG_NOT_LOADED, "warn");
        return true;
      }
      return false;
    };
    async function mutate(call) {
      try {
        await call();
      } catch (e) {
        ui.toast(String(e && e.message || e), "error");
      } finally {
        load();
      }
    }
    function addRole() {
      if (catalogNotLoaded()) return;
      setEditor({ role: null });
    }
    function editRole(role) {
      const target = role || selectedRole;
      if (!target) {
        ui.toast(MSG_SELECT_ROLE_EDIT, "warn");
        return;
      }
      if (catalogNotLoaded()) return;
      setEditor({ role: target });
    }
    async function deleteRole() {
      if (!selectedRole) {
        ui.toast(MSG_SELECT_ROLE_DELETE, "warn");
        return;
      }
      if (selectedRole.isAdmin) {
        ui.toast(MSG_ADMIN_ROLE_CANNOT_DELETE, "warn");
        return;
      }
      const ok = await ui.confirmDialog(
        TITLE_CONFIRM_DELETE,
        deleteRoleConfirmText(selectedRole.name),
        { danger: true, okLabel: "Delete" }
      );
      if (!ok) return;
      await mutate(() => api.deleteRole(selectedRole.id));
    }
    async function assignRole() {
      if (!selectedUser) {
        ui.toast(MSG_SELECT_USER_ASSIGN, "warn");
        return;
      }
      if (roles.length === 0) {
        ui.toast(MSG_NO_ROLES, "warn");
        return;
      }
      const username = selectedUser.username;
      const roleId = await pickRole(roles, username);
      if (roleId === null) return;
      const role = roles.find((r) => String(r.id) === String(roleId));
      if (!role) return;
      const currentRoleName = userRoles[selectedUser.id] != null ? userRoles[selectedUser.id] : null;
      if (!await confirmAssignment(username, currentRoleName, role, channelMap)) return;
      await mutate(() => api.assignUserRole(selectedUser.id, role.id));
    }
    async function removeRole() {
      if (!selectedUser) {
        ui.toast(MSG_SELECT_USER_REMOVE, "warn");
        return;
      }
      const ok = await ui.confirmDialog(
        TITLE_CONFIRM_REMOVE,
        removeRoleConfirmText(selectedUser.username),
        { danger: true, okLabel: "Remove" }
      );
      if (!ok) return;
      await mutate(() => api.removeUserRole(selectedUser.id));
    }
    async function applyEditor(built) {
      setEditor(null);
      await mutate(() => built.id != null ? api.updateRole(built.id, built) : api.createRole(built));
    }
    return /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "text-text-faint", style: { fontStyle: "italic", fontSize: 12 } }, IMMEDIATE_NOTICE), /* @__PURE__ */ React.createElement("div", { className: "panel" }, /* @__PURE__ */ React.createElement("div", { className: "panel-header" }, "Roles", canManage ? /* @__PURE__ */ React.createElement("div", { className: "panel-tools", style: { display: "flex", gap: 8 } }, /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: () => addRole() }, "Add"), /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: () => editRole() }, "Edit"), /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: () => deleteRole() }, "Delete")) : null), /* @__PURE__ */ React.createElement("div", { className: "panel-body flush" }, /* @__PURE__ */ React.createElement("table", { className: "dt", style: { width: "100%" } }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", { style: { width: 60 } }, ROLE_COLUMNS[0]), /* @__PURE__ */ React.createElement("th", null, ROLE_COLUMNS[1]), /* @__PURE__ */ React.createElement("th", null, ROLE_COLUMNS[2]))), /* @__PURE__ */ React.createElement("tbody", null, roles.length === 0 ? /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("td", { colSpan: 3, className: "text-text-faint", style: { padding: 12 } }, loading ? "Loading\u2026" : "No roles defined")) : roles.map((role) => /* @__PURE__ */ React.createElement(
      "tr",
      {
        key: role.id,
        className: String(role.id) === String(selectedRoleId) ? "selected" : "",
        style: { cursor: "pointer" },
        onClick: () => setSelectedRoleId(role.id),
        onDoubleClick: () => {
          setSelectedRoleId(role.id);
          editRole(role);
        }
      },
      /* @__PURE__ */ React.createElement("td", null, role.id),
      /* @__PURE__ */ React.createElement("td", null, role.name),
      /* @__PURE__ */ React.createElement("td", null, role.description)
    )))))), /* @__PURE__ */ React.createElement("div", { className: "panel" }, /* @__PURE__ */ React.createElement("div", { className: "panel-header" }, "User-Role Assignments", canManage && !usersError ? /* @__PURE__ */ React.createElement("div", { className: "panel-tools", style: { display: "flex", gap: 8 } }, /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: () => assignRole() }, "Assign Role"), /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: () => removeRole() }, "Remove Role")) : null), /* @__PURE__ */ React.createElement("div", { className: "panel-body flush" }, usersError ? /* @__PURE__ */ React.createElement("div", { className: "text-text-faint", style: { padding: 12 } }, "The user list could not be loaded (viewing assignments requires the manageUsers permission): ", usersError) : /* @__PURE__ */ React.createElement("table", { className: "dt", style: { width: "100%" } }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", { style: { width: 80 } }, USER_COLUMNS[0]), /* @__PURE__ */ React.createElement("th", null, USER_COLUMNS[1]), /* @__PURE__ */ React.createElement("th", null, USER_COLUMNS[2]))), /* @__PURE__ */ React.createElement("tbody", null, users.length === 0 ? /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("td", { colSpan: 3, className: "text-text-faint", style: { padding: 12 } }, loading ? "Loading\u2026" : "No users")) : users.map((user) => /* @__PURE__ */ React.createElement(
      "tr",
      {
        key: user.id,
        className: String(user.id) === String(selectedUserId) ? "selected" : "",
        style: { cursor: "pointer" },
        onClick: () => setSelectedUserId(user.id)
      },
      /* @__PURE__ */ React.createElement("td", null, user.id),
      /* @__PURE__ */ React.createElement("td", null, user.username),
      /* @__PURE__ */ React.createElement("td", null, userRoles[user.id] != null ? userRoles[user.id] : NONE_ROLE_LABEL)
    )))))), editor ? /* @__PURE__ */ React.createElement(
      RoleEditor,
      {
        role: editor.role,
        catalog,
        extGroups,
        channels,
        onApply: applyEditor,
        onCancel: () => setEditor(null)
      }
    ) : null);
  }
  platform.registerSettingsPanel({ label: "Role-Based Access Control", component: RolesPanel });
}

// web/plugin.jsx
var PERMISSION_VIEW = "View Roles";
async function register(platform) {
  const api = makeApi(platform.api);
  let permissions = null;
  async function fetchPermissions() {
    const [perms, taskPerms] = await Promise.all([
      api.getMyPermissions(),
      api.getExtensionTaskPermissions()
    ]);
    mergeExtensionTaskPermissions(taskPerms);
    permissions = perms;
  }
  try {
    await fetchPermissions();
  } catch (e) {
    console.warn("[rbac] permission load failed \u2014 failing closed:", e);
  }
  platform.setAuthorizationController(createController({
    getPermissions: () => permissions,
    // Fired (throttled, fire-and-forget) by the fail-closed path. On success,
    // re-set webPlugins to itself: setState always notifies, forcing the nav
    // and any mounted task panes to re-run checkTask with real permissions.
    reload: async () => {
      await fetchPermissions();
      platform.store.setState("webPlugins", platform.store.getState("webPlugins"));
    }
  }));
  if (permissions !== null && permissions.has(PERMISSION_VIEW)) {
    registerRolesPanel(platform, api);
  }
}
export {
  register
};
