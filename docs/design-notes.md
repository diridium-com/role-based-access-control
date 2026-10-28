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
