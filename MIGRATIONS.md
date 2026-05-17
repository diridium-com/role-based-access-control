# Schema Migrations

This plugin owns its own metadata schema in the OIE database (`rbac_role`,
`rbac_role_permission`, `rbac_role_channel`, `rbac_user_role`). This document
defines how to evolve that schema safely.

## Overview

OIE's `Migrator` base class does not track per-plugin schema versions. It
just calls `migrate()` on every server startup. That means the plugin is
responsible for:

1. Knowing what schema version is currently applied
2. Running only the steps that haven't been applied yet
3. Failing loudly if a step fails, not silently swallowing errors

The pattern below mirrors what the engine's own `ServerMigrator` does:
store a version, iterate forward, apply each step exactly once.

## Where the schema version is stored

The singleton `ConfigurationController.getInstance().saveProperty(PLUGIN_NAME, "schema_version", String.valueOf(n))`.
This is the standard OIE per-plugin key/value store and survives across
restarts and engine upgrades.

Read with `ConfigurationController.getInstance().getProperty(PLUGIN_NAME, "schema_version")`.
Returns `null` when missing, which means either a fresh install or a
pre-versioning install (see Backfill below).

## How migrations run on startup

`RbacMigrator.migrate()` is structured as a version loop:

```
int current = detectAndAlignSchemaVersion();  // detect actual state, realign stored value
if (current < 1) applyV1();                   // create the four tables
if (current < 2) applyV2();                   // add is_admin column
writeSchemaVersion(LATEST_VERSION);
```

**Detection runs on every startup, not only when the property is null.**
The engine's plugin uninstall drops the RBAC tables but does not clear
the plugin's {@code CONFIGURATION} properties, so on reinstall a stale
{@code schema_version} would otherwise convince the migrator that no
work is needed. Always detecting from {@code DatabaseMetaData} avoids
the issue and also tolerates other operational quirks (manual edits to
CONFIGURATION, partial restores, pre-versioning installs).

Each `applyVN()` method:

- Owns the DDL for that single step (one table, one column, one index, etc.)
- Branches on `getDatabaseType()` for per-dialect SQL when needed
- Throws `MigrationException` on failure
- **Never** catches and inspects exception messages

### Two-layer failure handling

`DefaultMigrationController.migrateExtensions` catches plugin
`MigrationException` and only logs it. The plugin will still get
registered and start, even if its schema is half-applied. Throwing from
`migrate()` alone is not enough.

The plugin therefore has a second line of defense in
`RbacServicePlugin.start()`:

1. After `migrate()` runs, re-read `schema_version` from CONFIGURATION
2. If it does not equal `LATEST_VERSION`, mark `MigrationStatus` as failed
   with the actual version, log an ERROR (not WARN), and skip
   `RbacRepository.init()`
3. Every public method on `RbacServlet` calls `requireMigrationOk()`
   first, which throws a `ClientException` with a clear `"plugin disabled:
   schema migration failed, check logs"` message

The auth controller deliberately does NOT consult `MigrationStatus` —
denying every authorization decision would render the entire engine
unusable, not just the RBAC UI. Instead, a failed migration causes auth
lookups to fail naturally (no role found in the missing/half-built tables
→ deny), which is the right fail-closed behaviour for users while the
RBAC servlet surfaces the clear error to the admin who can fix it.

## Adding a new schema version (recipe)

When the schema needs to change:

1. Increment `LATEST_VERSION` in `RbacMigrator`
2. Add a new `applyVN()` method for the new version
3. Add the matching `if (current < N) applyVN();` line to the loop
4. If the DDL differs by database, branch on `getDatabaseType()` and
   write SQL for all five supported dialects (Derby, MySQL, Oracle,
   PostgreSQL, SQL Server)
5. **Never edit prior `applyVN()` methods.** They have already run on
   customer installs. Append only.
6. Update this document with what version N does
7. Update `MigrationStatusTest` or add a new test class as appropriate

For non-trivial DDL (multiple statements, multiple tables), prefer a
numbered SQL script per dialect under `server/src/main/resources/` and
call `executeScript()`. For a single ALTER, inline the switch is fine
(see `applyV2`).

## Backfill for pre-versioning installs

Versions of the plugin before this migrator did not record a schema
version. On upgrade, we detect the actual database state:

```
if (readRawSchemaVersion() == null) {
    if (!rbac_role table exists)           writeSchemaVersion(0);   // fresh install
    else if (!is_admin column exists)      writeSchemaVersion(1);
    else                                   writeSchemaVersion(2);
}
```

Table and column existence checks query `DatabaseMetaData.getTables()`
and `DatabaseMetaData.getColumns()` from the JDBC connection, **not**
exception messages from probe queries.

**Identifier case** is handled by `namingCandidates(name)` which tries
the literal, upper-case, and lower-case forms:

- PostgreSQL stores unquoted identifiers as lowercase
- Derby, Oracle, SQL Server store them as uppercase
- MySQL is platform-dependent

After the first run with backfill logic, `schema_version` is set and the
backfill block is a no-op on subsequent startups.

## Testing a new migration

For every schema version added:

1. Install the **previous** plugin version against a clean database
   (Derby is fine for CI)
2. Create a role, save it, restart the server, confirm it persists
3. Install the new plugin version on top
4. Confirm the migration ran (look for the log line
   `"Applying RBAC schema vN ..."`)
5. Confirm `schema_version` in the CONFIGURATION table now matches
   `LATEST_VERSION`
6. Confirm prior data is preserved (roles, permission grants,
   user-role assignments)
7. Restart again. The migration should be a no-op. No DDL should run.
8. Repeat against at least one real RDBMS (Postgres or MySQL). Derby has
   the most permissive DDL and will let bugs slip through.

## Antipatterns to avoid

These are the antipatterns we replaced in this rewrite. Don't:

- **Catch a DDL exception and inspect the message text.** Error messages
  differ by vendor and version. A real failure (permissions, deadlock,
  syntax) looks identical to a benign "already exists" and gets silently
  logged as a warning.
- **Run unconditional ALTER on every startup.** Works the first time,
  fails noisily on every subsequent startup, and the failure is
  swallowed.
- **Skip versioning because the change is small.** Today's "one tiny
  column" becomes tomorrow's "wait, did that ever apply on the SQL
  Server install?". Track the version from the first migration onward.
- **Edit a prior `applyVN()` to fix a bug.** It already ran on customer
  databases. Add `applyV(N+1)` to correct it.
- **Use `DROP TABLE IF EXISTS` style cleanup at the top of a migration.**
  Destroys data. The only place `DROP TABLE` is acceptable is
  `getUninstallStatements()`.

## Current schema versions

| Version | Change |
| --- | --- |
| 1 | Initial tables: `rbac_role`, `rbac_role_permission`, `rbac_user_role`, `rbac_role_channel` |
| 2 | Add `is_admin` boolean column to `rbac_role` (BOOLEAN on Derby/Postgres/MySQL, NUMBER(1) on Oracle, BIT on SQL Server) |
