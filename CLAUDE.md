# RBAC Plugin for OIE (Open Integration Engine)

## Project Overview
Role-Based Access Control plugin for OIE/Mirth Connect 4.7.0 (1.1.4 is the last release for 4.6.0). Enforces dynamic roles with per-permission grants and channel-level restrictions. Replaces the default always-allow `DefaultAuthorizationController`.

## Project Structure
```
rbac/
├── server/    # RbacAuthorizationController, RbacServicePlugin, RbacServlet, RbacRepository, RbacMigrator, RoleTransfer*/RoleImport* (export and import), PluginSettingsGuard
├── shared/    # RbacServletInterface (JAX-RS), Role model, RoleImportResult/RoleImportRow
├── client/    # RbacClientPlugin, RbacSettingsPanel, RoleEditorDialog, SecureAuthorizationController
├── package/   # plugin.xml, sqlmap.xml, assembly.xml
├── e2e/       # real-engine end-to-end suite (run.py): the zip on the released engine, six databases, CI job `e2e`
```

## Build
On a fresh machine or wiped `~/.m2`, first install the engine jars into the local Maven repo. The script downloads the OIE release for the POM's `mc.version` and checks it against the SHA-256 pinned beside it in the POM (`oie.dist.sha256`, update it with `mc.version`):
```bash
./scripts/install-engine-jars.sh
```
Then:
```bash
mvn clean install    # 'mvn package' at the root also works (verified on a fresh repo; the release workflow uses it) — install additionally puts the jars in ~/.m2
```
The packaging step downloads Node.js v24.21.0 (frontend-maven-plugin), installs the web UI's dependencies with `npm ci`, builds `webadmin/web/plugin.js` (gitignored), and runs the web UI's unit tests in the test phase, so the first build needs network access beyond Maven Central.
Output: `package/target/rbac-1.3.0.zip`

## Architecture

### Server-Side Authorization
- `RbacAuthorizationController` extends `AuthorizationController` — registered via `<controllerClasses>` in plugin.xml
- `isUserAuthorized()` checks user's role permissions against operation-to-permission mapping
- On denial: throws `MirthApiException` with custom 403 reason phrase (e.g., "Missing permission: viewMessages") — RuntimeException bypasses MirthServlet's catch block, custom reason flows through to client error dialog
- Users assigned to a role flagged `is_admin` bypass all permission checks (admin safety). The bypass is by role flag, not by user ID — multiple admin users are supported. User ID 1 is only special at *seed* time (the seeder assigns it to the admin role on a fresh install)
- Infrastructure operations whitelisted for all authenticated users: `getStatus`, `getServerId`, and RBAC's own `getMyPermissions`/`getExtensionTaskPermissions` (whitelisted by their composite `Role-Based Access Control#…` runtime name, since they arrive through an extension servlet). Web plugin discovery/static resources (`getWebPluginPaths`/`getWebPluginResource`, native and `Web Support#…` forms) are also allowed for users without a role, though in practice they never reach them: the web client's first call after sign-in, `getCurrentUser`, is refused for a user with no role. Other Web Support operations are not exempt. `getAllUsers`/`getUser` were removed from the whitelist and are handled via `DEGRADABLE_OPERATIONS` instead (see below); `getServerSettings` was removed entirely (it leaked SMTP credentials) and now requires `SERVER_SETTINGS_VIEW`.
- `DEGRADABLE_OPERATIONS`: core engine reads annotated `@DontCheckAuthorized` (e.g. `getChannels`, `getAllUsers`, `getUser`) whose servlets self-degrade (empty/self-only) when the controller reports not-authorized. For these, the denial path returns `false` instead of throwing a 403, so the engine's graceful degradation works and limited-user login is not broken. Hand-maintained; re-verify on every engine bump.
- Extension-operation map is keyed by the **composite** `"<pluginName>#<op>"` name, because the engine wraps extension-servlet ops in `ExtensionOperation` (its `getName()` prepends the plugin name). Keying by the bare op name left RBAC's own management endpoints unenforced — a day-one privilege-escalation hole, now fixed. Side effect (intended): RBAC now enforces the permission-gated ops of *every* installed extension, not just its own (previously they all fell through to allow-unknown). The rare exception is a third-party plugin whose own read op is `@DontCheckAuthorized` and expects to self-degrade — RBAC returns a 403 rather than degrade, since only core reads are in `DEGRADABLE_OPERATIONS`. A plugin that registers a null/blank `extensionName` still falls through (keyed bare, misses).
- `PluginSettingsGuard`: the engine's `getPluginProperties`/`setPluginProperties` (`/extensions/{name}/properties`) arrive under the name as the URL spells it, and the engine matches settings with `WHERE CATEGORY = <name>`, which MySQL and SQL Server compare ignoring case. A lowercase "data pruner" got past Data Pruner's View Settings and wiped its settings (measured on MySQL). So, for anyone without the admin role, both calls are refused unless the name is exactly an installed plugin's or connector's, and rbac's own settings are refused outright (rbac never registers these two calls: claiming them collided with Data Pruner). Checked in `isUserAuthorized` with the admin-only operations, so the refusal is audited as a FAILURE
- Cache: `ConcurrentHashMap<userId, UserAuthCache>` invalidated on all write REST endpoints. `DeletedUserCleanup` removes a deleted user's `rbac_user_role` row on the request after the engine's delete (the engine has no user-delete hook, but it asks rbac to authorize `removeUser` first, so the approved target is held as pending and checked against the engine on the next authorization); the startup sweep (`deleteOrphanUserRoles`) covers users deleted while rbac wasn't loaded.

### Client-Side Authorization
- `SecureAuthorizationController` implements `com.mirth.connect.client.ui.AuthorizationController`
- Must be in package `com.mirth.connect.plugins.auth.client` (factory expects this exact FQCN)
- `RbacClientPlugin` constructor installs the controller via reflection into the factory's static field. This is a **deterministic override**, not a fix for a load failure: in 4.6.0 the factory's own `Class.forName` path can likely construct the controller too (same classloader that loads this plugin), but the reflection install guarantees it is installed early and wins. `stop()` uninstalls it (nulling the field only if it still holds our instance) so a same-JVM re-login to a non-RBAC server does not inherit a stale, fail-closing controller.
- `checkTask(taskGroup, taskName)` maps TaskConstants to permission strings; `Frame.setVisibleTasks()` calls this to hide/show buttons
- `initialize()` calls `getMyPermissions()` REST endpoint; lazy retry on first `checkTask()` if initial load fails
- Fail-closed: if permissions can't be loaded, tasks are denied
- Export Roles and Import Roles (`settings_Role-Based Access Control/doExportRoles`, `/doImportRoles`) are admin-only tasks, not permissions: `checkTask` answers them from an admin flag loaded with the permissions (only when the user holds View Roles: the current user's id, then `getUserRole`; a failure means not admin). Gated in the controller, not the panel, because `Frame.setVisibleTasks` re-runs `checkTask` whenever it shows tasks. Web twin: `ADMIN_ONLY_TASKS` in `task-permission-map.js` and `adminOnlyTasks` in `task-permission-map.json`
- The export and import flows live in `RoleTransferActions`, `RoleExportDialog`, `RoleImportDialog` and `RoleImportText` (wording, default ticks; web twin in `rbac-core.js`). The file is written as plain UTF-8, never through `Frame.exportFile`, which encrypts when export encryption is on

### Database
- 4 tables: `rbac_role`, `rbac_role_permission`, `rbac_role_channel`, `rbac_user_role`. Schema version 4 (`RbacMigrator`, `MIGRATIONS.md`): `rbac_role.restricted` says whether the role sees only its `rbac_role_channel` rows (possibly none, which is "no channels") or every channel. Before v4 an empty list meant every channel; v4 sets the flag for every role that had rows. `RoleService` stores a role sent with channels but no flag as restricted (older REST callers). `RbacChannelPlugin` (a `ChannelPlugin` listed in plugin.xml's server classes, the pattern simple-channel-history uses) is called by the engine inside a channel delete and removes every restriction row naming that channel at that moment, logging each role; `DeletedChannelSweep` runs at startup after the migration check for channels deleted while rbac wasn't loaded (one delete per row, skipped if the channel list can't be read). Both leave the role restricted, so nothing widens, and rbac's tables don't keep restrictions to deleted channels (owner's rule, 2026-11-04; a REST caller can still store an id the engine lacks, which the next start's sweep removes). The Administrators therefore have no "deleted channel" states
- MyBatis mapped statements in `sqlmap.xml` (namespace: `Rbac`, key: `all` = DB-agnostic)
- Pattern: `SqlConfig.getInstance().getSqlSessionManager().selectList(stmt("statementId"), params)`
- NEVER use raw JDBC (Connection, PreparedStatement, ResultSet)
- All repository methods have try-catch with `log.error` + rethrow
- Migrator: `getUninstallStatements()` returns `List<String>` with plain `DROP TABLE` (no IF EXISTS — Derby doesn't support it, OIE runs with ignoreErrors=true)

### REST API
- Path: `/extensions/rbac`
- Roles: GET/POST `/roles`, GET/PUT/DELETE `/roles/{roleId}`
- Users: GET `/users/{userId}/role`, POST `/users/{userId}/role/{roleId}`, DELETE `/users/{userId}/role`
- Permissions: GET `/permissions` (all available), GET `/my-permissions` (current user's granted permissions), GET `/permissions/extensions` (extension permission → publishing plugin, for the role editors' per-plugin headers), GET `/task-permissions` (extension task → permission, whitelisted for all users)
- Export/import: GET `/roles/_export?roleId=` (the file, `text/plain`), POST `/roles/_import?dryRun=&applyChannels=&matchChannelsByName=&pick=&planToken=` (the file as a `text/plain` body; preview, then apply the picked roles in one transaction). Format and rules: `docs/role-export-format.md`
- `@MirthOperation` annotations with `PERMISSION_VIEW = "View Roles"` and `PERMISSION_MANAGE = "Manage Roles"`. Export and import are admin-only: their operations are registered under View Roles and Manage Roles (so never unknown), `RbacAuthorizationController` refuses them to anyone without the admin role (`ADMIN_ONLY_OPERATIONS`, so the audit records a FAILURE, not a success), and `RoleTransferService` checks again

### Role Export and Import
- `RoleTransferFormat` writes and strictly reads the file (format 1; DOCTYPE refused; no XStream). Unknown elements, attributes or format versions refuse the whole file, so a newer file is never partly read
- `RoleImportPlanner` (no database writes) decides each role's action and the plan token; `RoleImportWriter` runs the picked rows inside `RbacRepository.importRoles`'s single transaction
- A file channel whose id isn't here but whose name exactly one channel here has is a match by name: always listed in `RoleImportResult.channelNameMatches`, and used only with `matchChannelsByName=true` (one setting, default off). The plan token covers the setting and the matches
- rbac's roles and assignments are not in the engine's backup (measured), by decision: the move steps are documented in `docs/role-export-format.md` instead
- The apply re-plans and answers 409 if the token from the preview no longer matches. The admin role is never exported or changed (the only SKIP). A restricted role with no channel found here is offered with `noChannelFound` and a note and comes in restricted to no channel, ticked like any new role (owner's decisions 2026-11-03 and 2026-11-04, reversing the 2026-10-30 skip); a new role imported with restrictions not applied also comes in restricted to no channel. Every row's `reason` is the full Notes text the clients show, composed on the server; `restrictedNow`/`restrictedAfter` drive the clients' "every"/"none" counts
- Every row carries the role here now (`existsHere`, `descriptionNow`, `permissionsNow`, `channelsNow`) and after the import (`descriptionAfter`, `permissionsAfter`, `channelsAfter`); each `RoleImportChannel` says how the file's channel was found (`BY_ID`, `BY_NAME`, `NOT_FOUND`), under which name and id here and in the file, and whether it is used. Both Administrators show a roles table (counts, the pick) with two detail tables for the selected role, one row per permission and per channel with Now and After columns, sortable, ids visible; nothing is marked as added or removed (owner's decisions, 2026-11-03); a change between every channel and some channels is a note in the reason
- The file reader compares role names exactly (Postgres, Derby and Oracle hold "Lab" and "LAB" as two roles). Names the database holds as one are caught by the planner (existing roles) and by `RoleImportWriter`'s in-transaction lookup (new roles)

### XStream Serialization (CRITICAL)
- Plugin DTOs MUST be whitelisted: `ObjectXMLSerializer.getInstance().allowTypes(emptyList, asList("com.diridium.rbac.**"), emptyList)`
- Required on BOTH client (RbacClientPlugin constructor) AND server (RbacServicePlugin.start())
- Client: `RbacClientPlugin.allowModelTypes()` also runs in `SecureAuthorizationController.loadPermissions` before the admin lookup. The engine builds the controller and loads permissions before it constructs the plugin, and a `Role` read before the whitelist stays refused for the session (measured: the RBAC tab's `getRoles` then failed for everyone)
- Without this: `ForbiddenClassException` on any REST call returning plugin types

### `getMyPermissions()` endpoint
- Whitelisted in auth controller for all authenticated users (needed for client-side UI)
- Admin-role holders: return ALL core permissions + ALL extension permissions (mirrors server-side bypass)
- Other users: returns their role's granted permissions from DB

## Key Design Decisions
- Admin access is by role flag (`is_admin`), not by user ID — supports multiple admin users; identified the same way on server and client (`Role.isAdmin()`)
- The admin role cannot be deleted, and an "admin floor" prevents removing/reassigning the last *live* admin user (enforced server-side by `AdminRoleGuard`; the floor count excludes orphaned rows for engine-deleted users). The admin role's name *can* be changed; the role editor disables the admin role's name, permission, and channel controls (only the description is editable) and re-sends its stored perms on save.
- The admin role's retention floor is the **core** permission set, not core+extension. The seeder grants only core perms, and admin access is by the flag regardless of stored perms, so requiring extension perms just made the admin role uneditable.
- `manageExtensions` is effectively an admin-equivalent grant: a holder can disable the RBAC extension, and on the next restart the engine reverts to the always-allow `DefaultAuthorizationController` (every user becomes admin). The role editor tags it with a warning tooltip; treat it as a privileged grant. This mirrors stock OIE (manageExtensions = install/enable/disable plugins = arbitrary code).
- `Manage Roles` is for delegating user management, not a security boundary: a holder can give their own account any role, the admin role included (measured on OIE 4.7.0 with rbac 1.2.0). Both role editors tag it with a warning tooltip, like `manageExtensions`.
- Role export and import are admin-only, rbac's only operations that are (decided 2026-10-31, before 1.3.0 shipped). Importing is admin-level power anyway (see Manage Roles above), and the admin role sees every channel, so an export can name each one. Separate Export Roles and Import Roles permissions were built first and removed before release; adding a grantable permission later is additive, removing a shipped one is not
- No role assigned = deny all (server-side), fail-closed (client-side). A role restricted to no channel (`restricted` true, no rows) sees no channel; the Administrators' role editors allow "Specific Channels" with nothing ticked for exactly that (owner's decision 2026-11-04, replacing the every-channel meaning of an empty list)
- Unknown operations = allow (server-side fallback for login, infrastructure); `@DontCheckAuthorized` reads instead return `false` to degrade gracefully (see `DEGRADABLE_OPERATIONS`)
- VIEW_SETTINGS intentionally unmapped in client — always shown; individual settings tabs gated by group-specific permissions

## Known Limitations & Operational Hazards
These are documented, not bugs to "fix" in the plugin — several live in the engine.

- **Ways RBAC can silently become allow-all.** (1) A routine engine upgrade: `mirthVersion` is matched by exact equality, so an un-rebuilt plugin is unloaded and the engine falls back to `DefaultAuthorizationController`. (2) A `manageExtensions` holder disabling the RBAC extension. Both revert to allow-all on restart with only a log line. After any engine upgrade, verify the RBAC tab and gating are active. During the disable→restart window there is transient mixed state (server still 403s, client shows no gating) and no in-UI way to re-enable RBAC — re-enable the extension and restart.
- **Channel restrictions are only as complete as the engine's redaction.** RBAC has no channel dimension in `isUserAuthorized`/`checkTask`; channel scoping is enforced solely through the engine's `redactChannel*`/`ChannelAuthorizer` machinery. Engine endpoints the engine does NOT redact therefore leak across the channel boundary to a suitably-permissioned restricted user: `updateChannel` (authorizes the path id but persists the body channel), `getAllStatistics` (bulk stats), `getChannelGroups` (group→member refs), `getServerConfiguration` (full channel/alert defs with backup permission), and all Alert CRUD (no channel dimension). These are engine limitations; the plugin cannot patch them.
- **`ChannelPanel.canViewChannelGroups` is cached by the engine before the plugin installs its controller**, so the channel-group view can show for a user lacking `viewChannelGroups` until the next client launch. Engine construction ordering; not fixable from the plugin.
- **In-panel edit controls on some settings tabs are not gated by `checkTask` (cosmetic).** The client hook only governs task-pane items (Refresh/Save/Import/Export), not buttons and editable cells the engine builds into a settings panel's body. The clearest case is the Configuration Map tab: a read-only user (`viewConfigurationMap`, not `editConfigurationMap`) has Save and Import hidden, but the panel's own Add/Remove buttons and editable Key/Value/Comment cells stay live, so they can type a value into a row they can never persist. This is cosmetic, not a hole: clicking Add fires `setSaveEnabled(true)`, but the engine re-runs `checkTask` inside `setVisibleTasks` (`Frame.java:1665`) and keeps Save hidden, and `setConfigurationMap` is gated server-side regardless. The engine exposes no per-widget authorization hook, and suppressing those buttons would take fragile reflection into each panel's private fields (`addButton`/`removeButton`/`configurationMapTable`), repeated per settings tab and per engine version.

## Debugging
- Server-side SLF4J: visible in OIE server logs
- Client-side SLF4J: DEBUG/INFO may NOT be visible — use `JOptionPane.showMessageDialog()` for quick diagnostics
- Remove diagnostic popups after confirming behavior
