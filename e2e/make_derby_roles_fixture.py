# SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
# SPDX-License-Identifier: MPL-2.0

"""Writes fixtures/roles-from-derby.xml: a role export file from a real engine on Derby, for the check that imports a
file from another engine (transfer_checks._transfer_from_another_engine). That check expects these roles and channel
names, so change both together. The checked-in file was written by a 1.3.0 pre-release build and its rbacVersion
attribute set to 1.3.0 by hand (the attribute is informational: the import shows it and nothing matches on it).

Usage: python3 -B make_derby_roles_fixture.py <oie_unix tarball> <rbac zip> <new work dir> <JAVA_HOME>
"""

import os
import sys

import engine as eng
import rbac as b

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "roles-from-derby.xml")


def main(tarball, zip_path, work, java_home):
    os.makedirs(work)
    e = eng.Engine(eng.unpack(tarball, os.path.join(work, "dist")), os.path.join(work, "engine"), java_home=java_home)
    e.configure({})
    try:
        api = e.start()
        ok, detail = b.install(api, zip_path)
        if not ok:
            raise SystemExit(f"install: {detail}")
        api = e.restart()
        lab_in, adt_out = b.new_id(), b.new_id()
        for cid, name in ((lab_in, "rbac e2e Derby Lab In"), (adt_out, "rbac e2e Derby ADT Out")):
            ok, detail = b.create_channel(api, cid, name)
            if not ok:
                raise SystemExit(f"create channel {name}: {detail}")
        # Derby holds "Lab" and "LAB" as two roles; MySQL and SQL Server hold them as one name.
        ids = [b.create_role(api, "e2e Derby Lab", ["viewChannels", "viewMessages"], [lab_in]),
               b.create_role(api, "e2e Derby LAB", ["viewChannels"], [lab_in, adt_out]),
               b.create_role(api, "e2e Derby everyone", ["viewDashboard"])]
        status, text = b.export_roles(api, ids)
        if status != 200:
            raise SystemExit(f"export: HTTP {status}: {text[:300]}")
        with open(OUT, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        print(f"wrote {OUT} from rbac {b.plugin_meta(api)[0]} on Derby: {sorted(b.parse_export(text)[1])}")
    finally:
        e.stop()


if __name__ == "__main__":
    main(*sys.argv[1:5])
