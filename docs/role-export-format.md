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
| `role` | one or more | One role. Role names are unique in a file. Names that differ only in case are different names. |
| `role/name` | yes | The role's name, at most 255 characters. |
| `role/description` | no | At most 1024 characters. Missing means empty. |
| `role/permissions` | yes | The role's permissions, one `permission` each, at most 255 characters, no repeats. May be empty. |
| `role/channels/@restricted` | yes | `false`: the role sees every channel, and lists none. `true`: it sees only the channels listed; with none listed, it sees no channel. |
| `channel/@id`, `channel/@name` | yes | A channel's id, and its name on the engine that wrote the file. The name is empty for a channel that had been deleted there. |

The admin role is never in a file. Neither are user assignments: a role comes in with no users.

## What an import refuses

The whole file is refused, with the reason, and nothing is written, if:

- its `formatVersion` is missing or isn't one this rbac reads. A file from a later rbac says so: "This file is format 2, written by rbac 1.4.0. This rbac reads format 1."
- a field above that is required is missing, or a value is too long;
- it has an element or attribute format 1 doesn't define, or text where format 1 has none;
- it isn't XML 1.0, or it has a DOCTYPE;
- two roles in it have the same name, or name the same existing role on this engine (a database can hold two names as one: MySQL's default collation ignores case and accents);
- it is larger than 5 MB.

Comments and whitespace between elements are fine. A later rbac that adds to the format gives it a new version, so an older rbac refuses the file instead of dropping what it doesn't understand.

## What an import does

An import is previewed first. The preview lists every role in the file with what would happen to it:

- **CREATE**: no role with that name exists here.
- **OVERWRITE**: one does, and the file's version differs. The existing role keeps its name and its users; its description, permissions and channels are replaced. A change from some channels to every channel, or the other way, is a note on the row.
- **UNCHANGED**: one does, and it already matches.
- **SKIP**: the role has the admin role's name, which an import never changes.

Every row shows the role as it is here now, when one exists (description, permissions, channels), and as the import would leave it. Each of the file's channels says how it was found here: by its id, by its id under a different name (the file's name is shown beside it), by its name only, or not at all. A role is either unrestricted (every channel) or restricted to its list, which may be empty: a restricted role with no channel sees none.

Then the user picks the roles to import (new roles start picked, overwrites don't), and the picked roles are written in one transaction: all of them, or none if anything fails. If any role the file names changed since the preview, the import is refused and has to be previewed again. Two new roles whose names this database holds as one, such as "Café" and "Cafe" on MySQL, both show as new in the preview; picking both is refused, with the reason, and writes neither.

Along the way:

- A role with the admin role's name is skipped. An import never changes the admin role.
- Every row carries a `reason`: the notes the Administrators show (why the admin row is skipped, what the import does to the role's channels, how many of the import's channels and permissions this engine lacks), or nothing when there is nothing to say.
- Permissions this engine doesn't offer are left out and listed. rbac stores any permission name it's given, and a stored grant for a disabled extension would take effect as soon as that extension is enabled.
- **Channel restrictions applied** (the default): each channel is matched by its id. A channel whose id isn't here, but whose name exactly one channel here has, is a match by name. The preview always marks the matches by name, and the import uses them only when it matches channels by name, which is off unless chosen. Channels found neither way are marked as not found. A restricted role none of whose channels are found is offered with `noChannelFound` set and a note: imported as it stands, it is restricted to no channel until an administrator sets its channels, which grants nothing, so the row starts ticked like any new role. If some of its channels match by name, the note says how many.
- **Channel restrictions not applied**: an existing role keeps the channel restrictions it has, and a new role is restricted to no channel until an administrator sets its channels. The preview says so on those rows.

## Role names

Role names are compared exactly as typed: "Lab" and "LAB" are two roles. Whether a database can hold both depends on the database. Derby, PostgreSQL and Oracle can. MySQL and SQL Server compare names ignoring case by default, and MySQL ignores accents too, so there only one of the two can exist. On those databases a role in a file matches an existing role whose name differs only in case, and an overwrite keeps the existing name. An import holding both "Lab" and "LAB" as new roles is refused there with "Rename one of them in the file.", and nothing is written. The rest of the file can still be imported without one of the two.

## Moving roles to a new engine

The engine's own backup (Backup Config in the Administrator) doesn't include rbac's roles or role assignments, and restoring one leaves rbac's roles as they are. It doesn't include the engine's users either. To move to a new engine:

1. Export the roles on the old engine.
2. Install rbac on the new engine and restart it.
3. Restore the engine's backup. Channels keep their ids, so the roles file matches them by id.
4. Create the users.
5. Import the roles file.
6. Assign each user a role.

## Who can export and import

Only a user holding the admin role can export or import, the preview included. A user with Manage Roles can already give their own account any role, so importing roles is admin-level work either way.

Any other user is refused (403) with "Exporting roles needs the admin role." or "Importing roles needs the admin role.", whatever permissions their role has. The engine's event log records the refusal as a failure.

## REST

- A role on the REST API (`/api/extensions/rbac/roles`) carries `restricted` since rbac 1.3.0 (schema version 4). A role sent without it but with `channelIds` is stored restricted, so older callers keep their meaning.
- `GET /api/extensions/rbac/roles/_export?roleId=3&roleId=7` answers the file as `text/plain; charset=UTF-8`. With no `roleId`, every role but the admin role. An id that doesn't exist, the admin role's, or a `roleId` with no value is refused (400).
- `POST /api/extensions/rbac/roles/_import` takes the file as a `text/plain` body and answers a `RoleImportResult`. Query parameters:
  - `dryRun`: `true` (the default) previews. The answer has a row per role in the file and a `planToken`. A row (`RoleImportRow`) carries the role's `index` in the file, `name`, `action`, `reason`, `droppedPermissions`, `matchedChannelCount`, `channels` (`FROM_FILE`, `KEPT` or `EVERY_CHANNEL`) and `noChannelFound`, then the role here now, when `existsHere` is true (`restrictedNow`, `descriptionNow`, `permissionsNow`, `channelsNow`), and the role after the import (`restrictedAfter`, `descriptionAfter`, `permissionsAfter`, `channelsAfter`). `channels` is `FROM_FILE`, `KEPT` or `NO_CHANNEL`. Each channel (`RoleImportChannel`) has its `id` and `name` here (for a channel not found here, the file's; `name` is null for a channel deleted here), `fileId` and `fileName` (the file's values; null in a now list), `match` (`BY_ID`, `BY_NAME` or `NOT_FOUND`) and `used`, whether the role is restricted to it after the import. An empty channel list means every channel.
  - `applyChannels`: `true` (the default) applies the file's channel restrictions.
  - `matchChannelsByName`: `true` also matches a channel whose id isn't on this engine by its name. The default is `false`. The answer's `channelNameMatches` lists every match by name either way, each with the channel's `name`, its id in the file (`fileChannelId`) and the id of the channel here (`channelId`). The plan token covers this setting, so preview again after changing it.
  - `pick` and `planToken`, for `dryRun=false`: the positions in the file (from 0) of the roles to write, and the preview's token. The answer has the rows written.

  An apply answers 400 for a refused file, a missing token, a pick that is out of range, skipped or unchanged, or two new names this database holds as one, and 409 if the roles changed since the preview.

Both answer 403 for a user without the admin role.
