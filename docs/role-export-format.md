# Role export files

rbac can write roles to a file and read them back, on the same engine or another one. This page describes the file and what an import does with it.

## The file, format 1

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rbacRoles formatVersion="1" rbacVersion="1.3.0" engineVersion="4.7.0">
  <role>
    <name>Lab users</name>
    <description>Lab interface support</description>
    <permissions>
      <permission>viewChannels</permission>
      <permission>viewMessages</permission>
    </permissions>
    <channels restricted="true">
      <channel id="9b33e5f2-6a4d-4c1e-9f0a-2d7c8e1b4a55" name="Lab Results In"/>
    </channels>
  </role>
  <role>
    <name>Everyone</name>
    <description/>
    <permissions/>
    <channels restricted="false"/>
  </role>
</rbacRoles>
```

| Element or attribute | Required | Meaning |
|---|---|---|
| `rbacRoles/@formatVersion` | yes | The format of the file. This page describes format 1. |
| `rbacRoles/@rbacVersion` | yes | The rbac version that wrote the file. |
| `rbacRoles/@engineVersion` | yes | The engine version it was written on. |
| `role` | one or more | One role. Role names are unique in a file, ignoring case. |
| `role/name` | yes | The role's name, at most 255 characters. |
| `role/description` | no | At most 1024 characters. Missing means empty. |
| `role/permissions` | yes | The role's permissions, one `permission` each, at most 255 characters, no repeats. May be empty. |
| `role/channels/@restricted` | yes | `false`: the role sees every channel, and lists none. `true`: it sees only the channels listed, at least one. |
| `channel/@id`, `channel/@name` | yes | A channel's id, and its name on the engine that wrote the file. The name is empty for a channel that had been deleted there. |

The admin role is never in a file. Neither are user assignments: a role comes in with no users.

## What an import refuses

The whole file is refused, with the reason, and nothing is written, if:

- its `formatVersion` is missing or isn't one this rbac reads. A file from a later rbac says so: "This file is format 2, written by rbac 1.4.0. This rbac reads format 1."
- a field above that is required is missing, or a value is too long;
- it has an element or attribute format 1 doesn't define, or text where format 1 has none;
- it has a DOCTYPE;
- two roles in it have the same name, ignoring case, or are the same role on this engine's database (a database such as MySQL that compares names without regard to case or accents);
- it is larger than 5 MB.

Comments and whitespace between elements are fine. A later rbac that adds to the format gives it a new version, so an older rbac refuses the file instead of dropping what it doesn't understand.

## What an import does

An import is previewed first. The preview lists every role in the file with what would happen to it:

- **CREATE**: no role with that name exists here.
- **OVERWRITE**: one does, and the file's version differs. The existing role keeps its name and its users; its description, permissions and channels are replaced.
- **UNCHANGED**: one does, and it already matches.
- **SKIP**: the role can't come in, and the preview says why.

Then the user picks the roles to import (new roles start picked, overwrites don't), and the picked roles are written in one transaction: all of them, or none if anything fails. If any role the file names changed since the preview, the import is refused and has to be previewed again.

Along the way:

- A role with the admin role's name is skipped. An import never changes the admin role.
- Permissions this engine doesn't offer are left out and listed. rbac stores any permission name it's given, and a stored grant for a disabled extension would take effect as soon as that extension is enabled.
- **Channel restrictions applied** (the default): each channel is matched by its id, then by its name if exactly one channel here has that name. Channels found neither way are listed. A restricted role none of whose channels exist here is skipped, because rbac stores "every channel" as an empty list and the role would otherwise see everything.
- **Channel restrictions not applied**: an existing role keeps the channel restrictions it has, and a new role sees every channel. The preview marks those new roles. They have no users until someone assigns one, so set their channels first.

## Permissions

Exporting needs **Export Roles** and **View Roles**. Importing, the preview included, needs **Import Roles** and **Manage Roles**, so an import can't do anything its user couldn't do by hand.

## REST

- `GET /api/extensions/rbac/roles/_export?roleId=3&roleId=7` answers the file as `text/plain`. With no `roleId`, every role but the admin role. An id that doesn't exist, or the admin role's, is refused (400).
- `POST /api/extensions/rbac/roles/_import` takes the file as a `text/plain` body and answers a `RoleImportResult`. Query parameters:
  - `dryRun`: `true` (the default) previews. The answer has a row per role in the file and a `planToken`.
  - `applyChannels`: `true` (the default) applies the file's channel restrictions.
  - `pick` and `planToken`, for `dryRun=false`: the positions in the file (from 0) of the roles to write, and the preview's token. The answer has the rows written.

  An apply answers 400 for a refused file, a missing token, or a pick that is out of range, skipped or unchanged, and 409 if the roles changed since the preview.
