<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (c) 2025-2026 Diridium Technologies Inc. -->

# Releasing

Every release is signed. CI builds an unsigned draft, the signed build is made where the YubiKey is, and it replaces the draft's assets before anyone publishes.

## 1. Bump the version

Change all of these in the commit you tag:

- `<revision>` in the parent `pom.xml`
- `version` in `oie.json`
- `version` in `webadmin/plugin.json`
- `version` in `webadmin/package.json`, and the two root entries in `webadmin/package-lock.json`

The release workflow fails unless the tag matches every one of them, since both CI and the signed build are made from the committed files.

When the engine version the plugin is built for (`plugin.supported.mc.versions` in `pom.xml`, normally `${mc.version}`) changes, set `minEngineVersion` and `maxEngineVersion` in `oie.json` to it as well. The engine loads a plugin only on the exact version it was built for, and the release workflow fails if `oie.json` says otherwise.

## 2. Tag

```bash
git tag vX.Y.Z && git push origin vX.Y.Z
```

`.github/workflows/release.yml` builds and tests against the OIE distribution matching the POM's `mc.version` and stages a **draft** release holding the unsigned `rbac-X.Y.Z.zip` and its `.sha256` sidecar. CI never publishes it. The build and tests run in a job whose token can only read the repository; a second job, the only one that can write, downloads the zip and creates or updates the draft.

## 3. Build the signed zip

Check out the tag on the machine with the YubiKey. If its local Maven repository does not have the engine jars for this `mc.version` yet, run `./scripts/install-engine-jars.sh` first. The `signing` profile also needs `yubikey-pkcs11.cfg` and `certchain.pem` in the repo root; both are gitignored. From the repo root:

```bash
mvn clean package -Psigning -Dsigning.storepass=<yubikey-pin>
```

The signed zip is `package/target/rbac-X.Y.Z.zip`. Run the commands below and in step 4 from `package/target/`.

Check every jar before it goes anywhere. Each must print `jar verified.` and exit 0:

```bash
unzip -q rbac-X.Y.Z.zip -d check
for j in check/rbac/*.jar; do jarsigner -verify -strict "$j" || echo "NOT SIGNED: $j"; done
```

`jarsigner -verify -verbose -certs` also prints when the signing certificate expires. The DigiCert timestamp keeps already-signed jars valid after that, but new releases need a current certificate.

## 4. Replace the draft's assets and publish

Regenerate the sidecar from the signed zip and replace both assets on the draft:

```bash
sha256sum rbac-X.Y.Z.zip > rbac-X.Y.Z.zip.sha256
gh release upload vX.Y.Z rbac-X.Y.Z.zip rbac-X.Y.Z.zip.sha256 --clobber
```

Review the draft, then publish it by hand. Never upload over a published release's assets; cut a new version instead.

## 5. Submit to the OIE Community Store

The store lists packages from the [community catalog](https://github.com/gibson9583/oie-community-catalog). Open a PR there, from a fork, adding `manifests/plugins/rbac/X.Y.Z.json` and refreshing `meta.json` from `oie.json`. The catalog README describes both files. The `sha256` must be computed from the **published, signed** zip, never from the CI build. The catalog's CI downloads the zip and checks that digest before the PR can merge, and the index is rebuilt on merge.

On the Diridium dev VM, the `publish-to-oie-store` Claude Code skill does this end to end. It refuses a release with unsigned jars or a stale sidecar.
