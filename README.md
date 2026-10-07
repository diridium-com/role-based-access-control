# Role Based Access Control for OIE

Role Based Access Control (RBAC) plugin for [Open Integration Engine](https://github.com/OpenIntegrationEngine/engine) 4.6.0. Enforces dynamic roles with per-permission grants and channel-level restrictions, replacing the engine's default always-allow authorization controller.

Web admin ready: the same zip ships both UIs. Role management and role-based task gating work in the desktop (Swing) Administrator and in the [OIE Web Administrator](https://github.com/diridium-com/role-based-access-control/wiki/Web-Administrator), with matching behavior in each. The web UI's permission gating is also more complete than Swing's, which cannot hide buttons inside panel bodies (an engine limitation that applies to all plugins); either way, denied operations always fail server-side. On servers where the Web Administrator isn't used, the web module is inert.

Full documentation is in the [wiki](https://github.com/diridium-com/role-based-access-control/wiki).

<img src="https://raw.githubusercontent.com/wiki/diridium-com/role-based-access-control/images/1.png" width="800" alt="Role-Based Access Control settings tab in the OIE Administrator">

<img src="https://raw.githubusercontent.com/wiki/diridium-com/role-based-access-control/images/2.png" width="600" alt="Role editor with grouped permission checkboxes and preset buttons">

## Prerequisites

- JDK 17
- Maven 3.x
- Network access on the first build: the engine jar script below downloads the OIE distribution, and the packaging step downloads Node.js v24.21.0 (via frontend-maven-plugin) to build the web administrator UI in `webadmin/`

## Build

The plugin compiles against engine jars that are not published to a public Maven repository. Install them into your local Maven repository once per engine version:

```bash
./scripts/install-engine-jars.sh
```

The script downloads the OIE release matching the POM's `mc.version`, checks it against that release's `sha256sums`, and installs the five jars the build needs.

Then build the plugin:

```bash
mvn clean install
```

This runs the Java tests and the web UI's unit tests; `-DskipTests` skips both. `mvn clean package` works too, it just doesn't copy the jars into your local Maven repository.

The distributable zip lands at:

```
package/target/rbac-1.1.2.zip
```

## Install

Install the zip through the Administrator's Extensions view and restart OIE. On first startup the plugin creates its four `rbac_*` tables and seeds an admin role assigned to the initial admin user.

## What RBAC enforces

RBAC checks each request against the permission the engine, or the plugin that owns the operation, declares for it. An operation that declares no permission is allowed for any logged-in user who has a role, and the server logs a warning each time (`RBAC: allowing unknown operation ...`). OIE 4.6.0 has dozens of these, mostly helpers behind screens that are already gated, such as the database connectors' table lookup (`getTables`). Gating them belongs in the engine. RBAC reads the engine's permission declarations at startup, so once the engine declares one, RBAC enforces it with no plugin change.

## License

MPL-2.0. See [LICENSE](LICENSE).
