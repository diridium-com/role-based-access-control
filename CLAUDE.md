# RBAC Plugin for OIE (Open Integration Engine)

## Project Overview
Role-Based Access Control plugin for OIE/Mirth Connect 4.6.0. Enforces dynamic roles with per-permission grants and channel-level restrictions. Replaces the default always-allow `DefaultAuthorizationController`.

## Project Structure
```
rbac/
├── server/    # RbacAuthorizationController, RbacServicePlugin, RbacServlet, RbacRepository, RbacMigrator
├── shared/    # RbacServletInterface (JAX-RS), Role model
├── client/    # RbacClientPlugin, RbacSettingsPanel, RoleEditorDialog, SecureAuthorizationController
├── package/   # plugin.xml, sqlmap.xml, assembly.xml
```

## Reference Code — ALWAYS check these first
- **Reference plugin:** `/Users/pcoyne/Documents/GitHub/simple-channel-history/` — canonical patterns for POMs, MyBatis, plugin.xml, XStream
- **Engine source:** `/Users/pcoyne/Documents/GitHub/engine/` — authoritative for API signatures, Frame behavior, authorization flow

## Build
On a fresh machine or wiped `~/.m2`, first install the 4.6.0 engine jars into the local Maven repo (the configured repsy repository does not carry 4.6.0):
```bash
ENGINE_DIR=/path/to/engine ./scripts/install-engine-jars.sh
```
Then:
```bash
mvn clean install    # 'mvn package' at the root also works (verified on a fresh repo; the release workflow uses it) — install additionally puts the jars in ~/.m2
```
The packaging step downloads Node.js v20.18.0 (frontend-maven-plugin) to build the `webadmin/` web-administrator UI, so the first build needs network access beyond Maven Central.
Output: `package/target/rbac-1.1.2.zip`

## Architecture

### Server-Side Authorization
- `RbacAuthorizationController` extends `AuthorizationController` — registered via `<controllerClasses>` in plugin.xml
- `isUserAuthorized()` checks user's role permissions against operation-to-permission mapping
- On denial: throws `MirthApiException` with custom 403 reason phrase (e.g., "Missing permission: viewMessages") — RuntimeException bypasses MirthServlet's catch block, custom reason flows through to client error dialog
- Users assigned to a role flagged `is_admin` bypass all permission checks (admin safety). The bypass is by role flag, not by user ID — multiple admin users are supported. User ID 1 is only special at *seed* time (the seeder assigns it to the admin role on a fresh install)
- Infrastructure operations whitelisted for all authenticated users: `getStatus`, `getServerId`, and RBAC's own `getMyPermissions`/`getExtensionTaskPermissions` (whitelisted by their composite `Role-Based Access Control#…` runtime name, since they arrive through an extension servlet). `getAllUsers`/`getUser` were removed from the whitelist and are handled via `DEGRADABLE_OPERATIONS` instead (see below); `getServerSettings` was removed entirely (it leaked SMTP credentials) and now requires `SERVER_SETTINGS_VIEW`.
- `DEGRADABLE_OPERATIONS`: core engine reads annotated `@DontCheckAuthorized` (e.g. `getChannels`, `getAllUsers`, `getUser`) whose servlets self-degrade (empty/self-only) when the controller reports not-authorized. For these, the denial path returns `false` instead of throwing a 403, so the engine's graceful degradation works and limited-user login is not broken. Hand-maintained; re-verify on every engine bump.
- Extension-operation map is keyed by the **composite** `"<pluginName>#<op>"` name, because the engine wraps extension-servlet ops in `ExtensionOperation` (its `getName()` prepends the plugin name). Keying by the bare op name left RBAC's own management endpoints unenforced — a day-one privilege-escalation hole, now fixed. Side effect (intended): RBAC now enforces the permission-gated ops of *every* installed extension, not just its own (previously they all fell through to allow-unknown). The rare exception is a third-party plugin whose own read op is `@DontCheckAuthorized` and expects to self-degrade — RBAC returns a 403 rather than degrade, since only core reads are in `DEGRADABLE_OPERATIONS`. A plugin that registers a null/blank `extensionName` still falls through (keyed bare, misses).
- Cache: `ConcurrentHashMap<userId, UserAuthCache>` invalidated on all write REST endpoints. A one-time startup sweep (`deleteOrphanUserRoles`) removes `rbac_user_role` rows for engine-deleted users.

### Client-Side Authorization
- `SecureAuthorizationController` implements `com.mirth.connect.client.ui.AuthorizationController`
- Must be in package `com.mirth.connect.plugins.auth.client` (factory expects this exact FQCN)
- `RbacClientPlugin` constructor installs the controller via reflection into the factory's static field. This is a **deterministic override**, not a fix for a load failure: in 4.6.0 the factory's own `Class.forName` path can likely construct the controller too (same classloader that loads this plugin), but the reflection install guarantees it is installed early and wins. `stop()` uninstalls it (nulling the field only if it still holds our instance) so a same-JVM re-login to a non-RBAC server does not inherit a stale, fail-closing controller.
- `checkTask(taskGroup, taskName)` maps TaskConstants to permission strings; `Frame.setVisibleTasks()` calls this to hide/show buttons
- `initialize()` calls `getMyPermissions()` REST endpoint; lazy retry on first `checkTask()` if initial load fails
- Fail-closed: if permissions can't be loaded, tasks are denied

### Database
- 4 tables: `rbac_role`, `rbac_role_permission`, `rbac_role_channel`, `rbac_user_role`
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
- `@MirthOperation` annotations with `PERMISSION_VIEW = "View Roles"` and `PERMISSION_MANAGE = "Manage Roles"`

### XStream Serialization (CRITICAL)
- Plugin DTOs MUST be whitelisted: `ObjectXMLSerializer.getInstance().allowTypes(emptyList, asList("com.diridium.rbac.**"), emptyList)`
- Required on BOTH client (RbacClientPlugin constructor) AND server (RbacServicePlugin.start())
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
- No role assigned = deny all (server-side), fail-closed (client-side)
- Unknown operations = allow (server-side fallback for login, infrastructure); `@DontCheckAuthorized` reads instead return `false` to degrade gracefully (see `DEGRADABLE_OPERATIONS`)
- VIEW_SETTINGS intentionally unmapped in client — always shown; individual settings tabs gated by group-specific permissions

## Known Limitations & Operational Hazards
These are documented, not bugs to "fix" in the plugin — several live in the engine.

- **Ways RBAC can silently become allow-all.** (1) A routine engine upgrade: `mirthVersion` is matched by exact equality, so an un-rebuilt plugin is unloaded and the engine falls back to `DefaultAuthorizationController`. (2) A `manageExtensions` holder disabling the RBAC extension. Both revert to allow-all on restart with only a log line. After any engine upgrade, verify the RBAC tab and gating are active. During the disable→restart window there is transient mixed state (server still 403s, client shows no gating) and no in-UI way to re-enable RBAC — re-enable the extension and restart.
- **Channel restrictions are only as complete as the engine's redaction.** RBAC has no channel dimension in `isUserAuthorized`/`checkTask`; channel scoping is enforced solely through the engine's `redactChannel*`/`ChannelAuthorizer` machinery. Engine endpoints the engine does NOT redact therefore leak across the channel boundary to a suitably-permissioned restricted user: `updateChannel` (authorizes the path id but persists the body channel), `getAllStatistics` (bulk stats), `getChannelGroups` (group→member refs), `getServerConfiguration` (full channel/alert defs with backup permission), and all Alert CRUD (no channel dimension). These are engine limitations; the plugin cannot patch them.
- **`ChannelPanel.canViewChannelGroups` is cached by the engine before the plugin installs its controller**, so the channel-group view can show for a user lacking `viewChannelGroups` until the next client launch. Engine construction ordering; not fixable from the plugin.
- **In-panel edit controls on some settings tabs are not gated by `checkTask` (cosmetic).** The client hook only governs task-pane items (Refresh/Save/Import/Export), not buttons and editable cells the engine builds into a settings panel's body. The clearest case is the Configuration Map tab: a read-only user (`viewConfigurationMap`, not `editConfigurationMap`) has Save and Import hidden, but the panel's own Add/Remove buttons and editable Key/Value/Comment cells stay live, so they can type a value into a row they can never persist. This is cosmetic, not a hole: clicking Add fires `setSaveEnabled(true)`, but the engine re-runs `checkTask` inside `setVisibleTasks` (`Frame.java:1665`) and keeps Save hidden, and `setConfigurationMap` is gated server-side regardless. The engine exposes no per-widget authorization hook, and suppressing those buttons would take fragile reflection into each panel's private fields (`addButton`/`removeButton`/`configurationMapTable`), repeated per settings tab and per engine version. Same family as the double-click/DELETE bypass paths above.

## Debugging
- Server-side SLF4J: visible in OIE server logs
- Client-side SLF4J: DEBUG/INFO may NOT be visible — use `JOptionPane.showMessageDialog()` for quick diagnostics
- Remove diagnostic popups after confirming behavior

## User Preferences
- NEVER add "Co-Authored-By: Claude" to commits
- Don't commit until explicitly asked
- Don't push to main directly — use feature branches with PRs
- Use "OIE" not "Mirth" in descriptions and conversation
- Use "Squash and merge" for PRs
- Discuss changes before proposing code
