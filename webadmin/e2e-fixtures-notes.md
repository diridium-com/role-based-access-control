# RBAC wire-shape pinning — live engine captures for the e2e fixtures

Captured 2026-07-14 against the running engine at `https://localhost:8443`
(rbac 1.1.0 installed; login `admin`, `Accept: application/json`,
`X-Requested-With` header set). Responses below are **verbatim** — use these
exact engine wire shapes in `e2e/` mock fixtures (the host's `mockEngine`
requires the single-root-key / bare-singleton forms as-is).

## GET /api/extensions/rbac/my-permissions — 200 application/json

Root key is `linked-hash-set`; the inner `Set<String>` is `{"string":[...]}`.
Admin-role holders get the full catalog (core + extension permissions):

```json
{"linked-hash-set":{"string":["viewAlerts","manageAlerts","viewDashboard","viewChannels","viewChannelGroups","manageChannels","clearStatistics","startStopChannels","deployUndeployChannels","viewCodeTemplates","manageCodeTemplates","viewGlobalScripts","editGlobalScripts","viewMessages","removeMessages","removeResults","removeAllMessages","processMessages","reprocessMessages","reprocessResults","importMessages","exportMessagesServer","viewTags","manageTags","viewEvents","removeEvents","manageUsers","manageExtensions","backupServerConfiguration","restoreServerConfiguration","viewServerSettings","editServerSettings","clearLifetimeStats","sendTestEmail","viewConfigurationMap","editConfigurationMap","editDatabaseDrivers","viewDatabaseTasks","manageDatabaseTasks","viewResources","editResources","reloadResources","Manage Roles","View Thread Viewer","View Roles","Save Settings","View Global Maps","View Connection Status","Start / Stop","View Settings","View Server Log"]}}
```

## GET /api/extensions/rbac/roles — 200 application/json

Root is `{"list":{"com.diridium.rbac.Role": ...}}` (FQCN key — Role has no
XStream alias). NOTE: with exactly one role the value is a **bare object**,
not a one-element array (XStream singleton collapse). Also note
`"channelIds":null` (null, not `""`) for an unrestricted role, and `isAdmin`
as a real JSON boolean:

```json
{"list":{"com.diridium.rbac.Role":{"id":1,"name":"Administrator","description":"Full access to all operations and channels","permissions":{"string":["manageExtensions","viewAlerts","exportMessagesServer","deployUndeployChannels","restoreServerConfiguration","manageChannels","processMessages","editResources","sendTestEmail","viewGlobalScripts","reloadResources","removeAllMessages","viewConfigurationMap","viewMessages","viewTags","startStopChannels","viewDatabaseTasks","removeMessages","reprocessResults","viewCodeTemplates","manageAlerts","viewResources","clearLifetimeStats","clearStatistics","viewChannels","backupServerConfiguration","editConfigurationMap","editServerSettings","manageCodeTemplates","manageDatabaseTasks","removeEvents","viewChannelGroups","viewEvents","viewServerSettings","manageUsers","viewDashboard","reprocessMessages","manageTags","importMessages","editDatabaseDrivers","editGlobalScripts","removeResults"]},"channelIds":null,"isAdmin":true}}}
```

## GET /api/extensions/rbac/permissions — 200 application/json

Same `linked-hash-set` shape (and, on this install, the same content) as
`my-permissions` — the last eight entries are extension permissions
(rbac's own "View Roles"/"Manage Roles" plus dashboard-plugin ones).

## GET /api/extensions/rbac/task-permissions — 200 application/json

Root key is `linked-hash-map`; entries are `{"string":[key,value]}` pairs.
Keys here are bare task names declared by installed extensions:

```json
{"linked-hash-map":{"entry":[{"string":["doSave","Save Settings"]},{"string":["doStop","Start / Stop"]},{"string":["doStart","Start / Stop"]},{"string":["doRefresh","View Settings"]}]}}
```

## GET /api/extensions/rbac/users/{userId}/role — 200 application/json

Single Role root key is the FQCN:

```json
{"com.diridium.rbac.Role":{"id":1,"name":"Administrator","description":"Full access to all operations and channels","permissions":{"string":["manageExtensions","viewAlerts","exportMessagesServer","deployUndeployChannels","restoreServerConfiguration","manageChannels","processMessages","editResources","sendTestEmail","viewGlobalScripts","reloadResources","removeAllMessages","viewConfigurationMap","viewMessages","viewTags","startStopChannels","viewDatabaseTasks","removeMessages","reprocessResults","viewCodeTemplates","manageAlerts","viewResources","clearLifetimeStats","clearStatistics","viewChannels","backupServerConfiguration","editConfigurationMap","editServerSettings","manageCodeTemplates","manageDatabaseTasks","removeEvents","viewChannelGroups","viewEvents","viewServerSettings","manageUsers","viewDashboard","reprocessMessages","manageTags","importMessages","editDatabaseDrivers","editGlobalScripts","removeResults"]},"channelIds":null,"isAdmin":true}}
```

## Not yet pinned (defer to live pass step C.5)

- **No-role user** `GET /users/{id}/role`: every current user (ids 1–4) holds
  the Administrator role via the fresh-install seeder, so the null-assignment
  response (expected: 204/empty body) could not be captured. Pin it after
  creating the test user in the live checklist.
- **Singleton/empty Set on a real role** (e.g. one permission → `{"string":"x"}`,
  restricted `channelIds` → `{"string":[...]}`): capture when the "Read Only"
  test role exists. `rbac-api.js` already tolerates all of these shapes
  (verified against synthetic values).
- **Write payload echoes**: `POST /roles` response shape for a created role —
  expected `{"com.diridium.rbac.Role":{...}}` like `users/{id}/role`.
