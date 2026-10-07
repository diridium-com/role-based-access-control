# Role-Based Access Control

**Server-side role-based access control** for Open Integration Engine. It
replaces the engine's default authorization controller, which allows every
operation for every logged-in user, with one that checks each REST call against
the caller's role.

- **Dynamic roles**: create, edit and delete roles from the Settings tab.
  Changes take effect immediately, with no restart.
- **Per-permission grants**: every engine permission, grouped by function in
  the role editor, plus the permissions installed plugins publish, grouped by
  plugin.
- **Channel restrictions**: limit a role to specific channels. The engine
  filters channel lists, the dashboard, messages and deploys to the role's
  channels.
- **Enforced on the server**: a request sent with curl gets the same check as
  one from the Administrator. A denial returns a 403 naming the missing
  permission, and both administrators hide the tasks a role doesn't grant.
- **Lockout guards**: the admin role can't be deleted, and the server refuses
  to remove the last admin user.
- **Assignment preview**: before a role is assigned, a confirmation shows its
  channel scope and its full permission list.
- **Both administrators**: the Swing Administrator and the OIE Web
  Administrator, from the same zip.

## Before you install

- **A user with no role is denied everything.** Install seeds an admin role and
  assigns it to the initial admin user. Give every other user a role before
  they need to log in.
- **`manageExtensions` is admin-equivalent.** A holder can disable RBAC, and
  after the next restart the engine reverts to allowing everything.
- **Check RBAC after every engine upgrade.** The engine unloads a plugin built
  for a different engine version and falls back to allowing everything. Make
  sure the Role-Based Access Control settings tab is there before letting users
  back in.

## Compatibility

Requires Open Integration Engine **4.6.0** (Java 17+). A restart is required
after install. On servers that don't use the Web Administrator, the web module
is inert.

Full documentation is in the
[wiki](https://github.com/diridium-com/role-based-access-control/wiki).
