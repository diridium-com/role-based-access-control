<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (c) 2026 Diridium Technologies Inc. -->

# Design notes

Why parts of this repository are shaped the way they are. Dated; later entries are added below, earlier ones are not rewritten.

## 2026-10-26: the end-to-end suite on a real engine

`e2e/run.py` installs the plugin zip into the released OIE engine through the engine's own installer, the way an administrator does, and drives it over the engine's REST API as real signed-in users. CI runs it on every database the engine supports (Derby, PostgreSQL, MySQL, SQL Server with the jTDS and the Microsoft driver, Oracle), on Java 17 and on Java 21, the Java the OIE 4.7.0 installers bundle. Nothing is mocked. Each scenario gets a new database and a freshly unpacked engine.

**fresh** covers the first install and every feature:

- the schema steps, the four tables, `schema_version` 2, and the seeded Administrator role, which every user that exists at install time is assigned to;
- creating, reading, updating and deleting roles, including a name with characters outside Latin-1 (creating a role on Oracle is what failed in 1.1.2);
- the admin floor: the last admin can't lose the role, be moved, or be deleted, and the admin role can't be deleted, lose a permission, or be limited to channels;
- what each role can and can't do, with the exact `Missing permission: ...` reason: no role, read-only, limited to some channels, View Roles, Manage Roles, a second admin user, and users without Manage Users, who see only themselves and can change only their own password;
- Data Pruner, an extension bundled with the engine and gated by its own grants, so extension operations are checked for an extension other than rbac itself;
- a permission change applying on the user's next request, the startup sweep of a deleted user's assignment, and a restart that keeps everything and runs no schema step.

**upgrade-X** starts from each published release in `e2e/upgrade-sources.txt`. Releases built for OIE 4.6.0 start on 4.6.0, and the engine is upgraded under them before the new zip goes in, which is the path their users take.

**uninstall** removes the plugin, checks its tables are gone, and reinstalls it.

### Checks shaped by measured behavior

- **Channel restrictions** are applied by the engine, and in three different ways: lists are filtered, single-channel calls are refused, and bulk changes silently skip the channels the user may not touch. The checks follow each: a list holds only the allowed channels, a refused call is a 403, and a bulk remove is judged by what the admin sees afterwards.
- **While the engine runs a release built for another engine**, as in the middle of an engine upgrade, it doesn't load rbac and falls back to allowing everything. The same happens after an uninstall. Both are recorded as a NOTE, not a failure: they are the engine's behavior, not rbac's. After any engine upgrade, check that the RBAC tab and its gating are active.
- **A reinstall seeds the admin role again for every existing user**, because the tables it finds are empty, as on a first install. The uninstall scenario checks for that.
- **1.1.2 on Oracle** fails to create its admin role (issue #10), so every user, admin included, is refused. Nothing can be set up on it, so its upgrade scenario on Oracle checks that the new release recovers: it creates the admin role and assigns every existing user to it.

The channel the tests create is the engine's own no-op test channel (`e2e/fixtures/channel.xml`, from OpenIntegrationEngine/engine at v4.7.0), under a new id and name. It is never deployed.

### Not covered

- The Swing Administrator's gating of buttons and menus. The `browser` job covers the web Administrator, against a mocked API.
- The engine endpoints that don't filter by channel, such as bulk statistics and alerts. rbac can't restrict those, since the engine applies channel restrictions itself.
- What happens after a failed schema migration; the unit tests cover it.
- Table checks on Derby: it runs inside the engine, so those checks are a NOTE there, and the REST checks still run.

## 2026-10-28: SQL Server text columns become NVARCHAR (schema step v3)

SQL Server's `VARCHAR` holds only the characters of the column's code page; anything else is saved as `?`. rbac's SQL Server tables used `VARCHAR`, so on the default collation a role named `e2e Rôle ünïcödé 角色` read back as `e2e Rôle ünïcödé ??`, and a second role with that name got HTTP 500 from the unique constraint instead of 409 (issue #34). The other databases' `VARCHAR` already holds Unicode.

The create script now uses `NVARCHAR`, as the engine's own SQL Server schema does, and schema step v3 converts existing installs: `rbac_role.name`, `rbac_role.description` and `rbac_role_permission.permission`. The engine handles its own columns differently: a fresh install is `NVARCHAR` throughout, but no migration step converts older columns, so `ALERT.NAME`, created `VARCHAR(255)` by its 3.0 step, stays that way on an upgraded database. rbac converts because its tables are small and the step is tested on the upgrade paths users take. Names already saved with `?` can't be recovered.

A column can't change type under a unique constraint, so v3 drops the constraint, alters the column and adds it back. The one on `rbac_role.name` had a name SQL Server generated; v3 looks it up and adds it back as `uq_rbac_role_name`. Each statement checks before it acts, so a run that stopped halfway finishes on the next startup. On the other databases v3 does nothing.

The end-to-end suite expects `schema_version` 3. On SQL Server every upgrade scenario runs v3 and nothing else, and every upgrade checks that a role name with characters outside Latin-1 reads back intact and that a second role with it is refused.

## 2026-10-30: role export and import on the server

Superseded in part before release: export and import became admin-only, and names are compared exactly. See 2026-10-31 below.

Roles can be exported to a file and imported on the same engine or another one (issue #39). The format, and what an import does with a file, are in [role-export-format.md](role-export-format.md).

The work is on the server, behind two new permissions, Export Roles and Import Roles. The Administrators only upload, preview and confirm. That puts the permission checks where they can't be skipped, makes the import one transaction, and lets channel matching see every channel on the engine, not only the ones the importing user can see. An operation declares one permission, so the second each one needs is checked in the servlet: export also needs View Roles, because the file shows every role in it, and import also needs Manage Roles, so it can't write anything its user couldn't write by hand.

The format declares its version, and reading it is strict: a file with an element, attribute or version this rbac doesn't know is refused whole, with the reason. The alternative, reading what it can, is how a newer file loses a field without anyone noticing. The parser refuses any DOCTYPE, so external entities and entity expansion never come into it, and XStream isn't used, so nothing in a file can name a Java type.

An import is previewed, then applied with the roles the user picked and the token the preview returned. The apply plans the file again and is refused (409) if the token differs, so it writes exactly what the user saw. One thing no preview can see: two new names the database treats as one, such as "Café" and "Cafe" under MySQL's default collation, which ignores accents. The file's own check ignores case only, so before inserting each new role the apply asks the database, inside the transaction, whether the name is taken, and stops with the reason if it is. The admin role is never exported and never changed by an import. A restricted role whose channels are all missing on this engine is skipped rather than written with an empty channel list, which rbac reads as every channel.

### Not covered

- A database failure partway through an import, except on MySQL. There the end-to-end check of two names that differ only by an accent inserts the first role, stops at the second, and neither is left. On the other databases the rollback is tested with a mocked session.
- The Swing and web Administrators' buttons for export and import come in a separate change.

## 2026-10-31: export and import are for the admin role only

Before 1.3.0 shipped, the Export Roles and Import Roles permissions above were taken out again. Only a user holding the admin role can export or import now. Importing roles was admin-level power with or without its own permission: a user with Manage Roles can already give their own account any role. An export by a user restricted to some channels would also have named channels that user can't see, and the admin role sees every channel. Starting narrow is the safe direction: a grantable permission can be added later without changing anyone's roles, while taking one away after release would change what existing roles can do.

The operations are still registered, export under View Roles and import under Manage Roles, because rbac allows any operation it has no permission for. rbac's authorization check refuses them to any user without the admin role, with "Exporting roles needs the admin role." or "Importing roles needs the admin role.", before the permission lookup. Refusing there rather than in the servlet matters for the audit: a refusal in the servlet comes after the check has already recorded the call as authorized, so the event log would show a success. The servlet checks again for a caller that doesn't go through rbac's check.

The file reader now compares role names exactly. Postgres, Derby and Oracle hold "Lab" and "LAB" as two roles, and refusing names that were equal ignoring case meant an export holding both could not be imported anywhere. Where the database holds two of the file's names as one, the import still says so: the preview refuses the file when two of them are one existing role, and the apply refuses two new ones the database treats as one name.

A preview row for an overwrite now lists the permissions and channels it adds and removes, and whether the description changes, so the user sees what an overwrite does before picking it. A change between every channel and some channels is a note instead, since every channel has no list to compare. The import's audit event now records each written role's permissions and channels: the file is kept out of the engine's audit of the call, so without them the event named the roles and not what they were given.

## 2026-11-01: channels matched by name, the engine's backup, role names, and plugin settings

**A channel matched only by name is used only when the import matches channels by name.** A file from another engine names its channels by that engine's ids. Until now an import fell back, silently, to a channel here with the same name. A channel with the same name isn't necessarily the same channel, and restricting a role to the wrong one shows its users the wrong messages. Matching by name is now a choice, off unless chosen, and the preview lists every match by name either way, so the importer sees what it would use. One setting rather than a choice per channel: where channels match only by name, as between test and production engines built by hand, a channel with the same name is meant to be the same one, and the list in the preview is there for the exceptions. A choice per channel can be added later without changing the setting.

**rbac's roles are not in the engine's backup.** Measured on OIE 4.7.0: the engine's backup (`GET /api/server/configuration`) holds rbac's `schema_version` and nothing else of rbac's, and restoring it leaves rbac's roles as they were. Putting the roles in it was considered and dropped:

- The backup doesn't carry the engine's users either, so moving to a new engine is manual work already, and importing a roles file is one more step in it.
- A restore onto the same engine loses nothing, since rbac's roles live in its own tables.
- The engine's Backup and Restore permissions can be given to roles without the admin role, which would be a second way to read and replace every role, beside an import only the admin role may use.
- It can be added later without changing anything that exists. A restore that deletes roles, once shipped, could not be taken back as easily.

The steps for a move are in [role-export-format.md](role-export-format.md#moving-roles-to-a-new-engine).

**Role names are compared exactly as typed.** To rbac, "Lab" and "LAB" are two names. MySQL and SQL Server compare names ignoring case by default, so there only one of them can exist: the end-to-end suite measured the second refused (409) on MySQL and with both SQL Server drivers, and kept on Derby, PostgreSQL and Oracle. Making rbac ignore case on every database was considered and dropped. The import says what to do when a file holds a pair the database can't hold.

**The engine's plugin-settings calls.** `GET` and `PUT /api/extensions/{name}/properties` are checked under the name exactly as the URL spells it, and the engine reads and writes the settings with `WHERE CATEGORY = <name>`. On MySQL, which compares that ignoring case, a user whose role had only View Channels read Data Pruner's settings as "data pruner", past the View Settings permission rbac holds for "Data Pruner", and wiped them with one save. Measured on OIE 4.7.0 with MySQL 8.4; on Derby the same requests reached nothing. rbac now refuses those two calls, to anyone without the admin role, for a name that isn't exactly an installed plugin's or connector's. rbac never registered a permission for its own settings, so they were open to any role; they are for the admin role only now.

### Accepted

- A database failure partway through an import is undone by the database: the import is one transaction, never committed after a failure. The end-to-end suite shows it on MySQL only. Making an import fail on purpose on the other databases would need a test switch in the shipped plugin.
- From the code, not measured: when two admins change roles at the same moment, the one whose import loses the race gets HTTP 500 rather than "preview again", and nothing is half-written.

### Tests added

- An import of a file exported on Derby (`e2e/fixtures/roles-from-derby.xml`, made by `e2e/make_derby_roles_fixture.py`), on every database: its channels are listed as matches by name and not used until the import matches channels by name, then its roles come in with this engine's channel ids. "e2e Derby Lab" and "e2e Derby LAB" are both written on Derby, PostgreSQL and Oracle, and refused with the reason on MySQL and SQL Server, where the rest goes in without one of them.
- After each upgrade, the old release's restricted role is exported, deleted and imported back with its channel.
- The plugin-settings calls as a read-only user: rbac's own settings, and Data Pruner's and rbac's under other cases and with a trailing space.

## 2026-11-03: the export and import tables show every role's details

The first import preview (2026-11-02) was one table with a Details cell that joined everything with semicolons, and a New row showed nothing about the role. The owner's review on a demo instance found it poor: the channels per role could not be seen, the by-name matches were listed file-wide in a block that read as tick boxes, "removed" confused, and nothing showed the role as the import would leave it. Both dialogs are now one flat table with a column per fact, and the dialogs grow to fit; a wide table is not a cost when each column holds one kind of fact.

**Now and After, side by side, nothing marked.** The import table has Description, Permissions and Channels twice: as the role is on this engine now (empty for a role that isn't here) and as the import would leave it. The server sends both (`existsHere`, the now and after fields of `RoleImportRow`) and no longer sends the added and removed lists, which said the same thing in a form that confused. Each list cell has one entry per line. A role with no channel in its list sees every channel, which the cell says in words.

**Every channel says how it was found.** A channel in the file is matched by id first; a channel renamed on this engine since the export keeps its id, so it is found by id and the cell shows the name here with the file's name beside it, which is how an administrator can tell a rename from a different channel. A match by name only is marked, and marked "not used" until the match-by-name box is ticked, which replaces the file-wide list; one line under the tick boxes says how many such channels there are. A channel found neither way is marked as not found, under the file's name.

**The export table.** Picking whole roles with their description, permissions and channels in view, so the exporter sees what the file will hold. The channel names come from the client's channel list; an id the list doesn't have is a deleted channel, and when the list didn't load the cell says so instead of guessing.

### Tests

- Server: the planner's tests cover each way a channel is found, the rename, a deleted channel in a now list, the empty now fields of a new role, and that a skipped row still describes the file's content. Client and web: a test per cell helper with the agreed strings. Playwright: the headers and cells of both tables, the rename, a by-name channel before and after ticking the box, the hint line. e2e on the six databases: the now and after fields of an overwrite, a new role, channels not applied, a not-found channel, the admin row, a renamed channel, and a file from another engine with and without matching by name.

### Not covered

- The Swing table's wrapping and row heights are checked by eye on the VM (screenshots in the plans folder), not by a unit test.

## 2026-11-02: Export Roles and Import Roles in both Administrators

Users holding the admin role get Export Roles and Import Roles on the Role-Based Access Control settings tab, in the desktop and the web Administrator, with the same dialogs and wording. Export picks the roles and saves the server's file as is. Import previews the file, lets the user pick roles, and has two tick boxes: "Apply channel restrictions from the file" and, under it, "Also match channels by name when the id isn't found". Changing either previews again, and a row keeps the user's tick when it is still the same role with the same action. A failed import shows the server's message and previews again.

**Who sees the buttons.** There is no permission for them, so a client has to know whether the signed-in user holds the admin role, and the permission list can't tell (an admin's list looks like a user granted everything). Measured on OIE 4.7.0: rbac's `GET /users/{id}/role` for the user's own id answers the role with its `isAdmin` flag for the admin and for a View Roles user, and 403 for a user without View Roles, who can't be an admin and can't open the tab. So each Administrator asks it once with the permissions, only for a user holding View Roles. The gating sits in the authorization controllers, not in the panel: the Swing frame runs the controller again whenever it shows a panel's tasks, so a panel hiding its own buttons would be undone.

**Why the Swing controller registers rbac's classes itself.** The Swing Administrator builds rbac's authorization controller and loads its permissions before it constructs the rbac plugin, which is where rbac's classes are allowed through the client's XStream serializer. The admin lookup is the first call there that returns one of rbac's classes. Measured on OIE 4.7.0 before the fix: the lookup's `Role` was refused, and the refusal stayed for the session, so the RBAC tab's own role list failed with `ForbiddenClassException` for every user and the buttons stayed hidden. The same run against main's build opened the tab cleanly. So `RbacClientPlugin.allowModelTypes()` runs in the controller before the lookup as well as in the plugin's constructor; adding the same pattern twice is harmless.

**The file is plain XML.** The Swing Administrator writes it as UTF-8 itself. The engine's own export helper encrypts the file when the engine's export encryption is on, which would make it unreadable on another engine.

**What the web client receives.** The engine's JSON turns a list of one into a bare object or string, an empty list into `null`, and the format version into a number. `normalizeImportResult` in `rbac-api.js` is the only place that knows; its tests use the answers a real engine gave.

### Tests

- Unit tests for the gating, the wording and the default ticks on both sides, and the web parsing against captured answers. Playwright, against the web client CI pins, covers who sees the buttons, export, the preview, the two tick boxes, picks, a failed import and a refused file.
- On a real OIE 4.7.0 engine: the Swing Administrator driven in-process under xvfb (it needs a Java with JavaFX), and the web Administrator through Web Support 1.2.1 in headless Chromium, as the admin and as a View Roles user. As the admin, both exported, imported the Derby roles file with matching by name, showed the refusal when a role was created behind the preview, and imported after the fresh preview, keeping the ticks; the server then held the new roles with this engine's channel ids. The View Roles user saw neither button.

### Not covered

- The Swing Administrator is not driven in CI. Its check runs on the VM before a release. The class-registration order above is covered only by that check.
