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
