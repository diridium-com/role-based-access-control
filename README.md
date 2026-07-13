# Role Based Access Control for OIE

Role Based Access Control (RBAC) plugin for [Open Integration Engine](https://github.com/OpenIntegrationEngine/engine) 4.6.0. Enforces dynamic roles with per-permission grants and channel-level restrictions, replacing the engine's default always-allow authorization controller.

## Prerequisites

- JDK 17
- Maven 3.x
- A local checkout of the OIE engine source at version 4.6.0, built with its Gradle build (the plugin compiles against engine jars that are not published to a public Maven repository)

## Build

First, install the engine jars into your local Maven repository. Build the engine checkout first so its jars exist, then run:

```bash
ENGINE_DIR=/path/to/engine ./scripts/install-engine-jars.sh
```

If `ENGINE_DIR` is unset, the script defaults to `../engine` relative to the repo.

Then build the plugin:

```bash
mvn clean install
```

Use `install`, not `package`. The multi-module build requires the shared module to be installed into the local repository for the sibling modules to resolve.

The distributable zip lands at:

```
package/target/rbac-1.1.0.zip
```

## Install

Install the zip through the Administrator's Extensions view and restart OIE. On first startup the plugin creates its four `rbac_*` tables and seeds an admin role assigned to the initial admin user.

## License

MPL-2.0. See [LICENSE](LICENSE).
