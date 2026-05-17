IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'rbac_role') AND type in (N'U'))
CREATE TABLE rbac_role (
    id          INTEGER IDENTITY(1,1) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(1024)
)

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'rbac_role_permission') AND type in (N'U'))
CREATE TABLE rbac_role_permission (
    id          INTEGER IDENTITY(1,1) PRIMARY KEY,
    role_id     INTEGER NOT NULL FOREIGN KEY REFERENCES rbac_role(id) ON DELETE CASCADE,
    permission  VARCHAR(255) NOT NULL,
    CONSTRAINT uq_role_perm UNIQUE (role_id, permission)
)

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'rbac_user_role') AND type in (N'U'))
CREATE TABLE rbac_user_role (
    id          INTEGER IDENTITY(1,1) PRIMARY KEY,
    user_id     INTEGER NOT NULL UNIQUE,
    role_id     INTEGER NOT NULL FOREIGN KEY REFERENCES rbac_role(id) ON DELETE CASCADE
)

IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'rbac_role_channel') AND type in (N'U'))
CREATE TABLE rbac_role_channel (
    id          INTEGER IDENTITY(1,1) PRIMARY KEY,
    role_id     INTEGER NOT NULL FOREIGN KEY REFERENCES rbac_role(id) ON DELETE CASCADE,
    channel_id  CHAR(36) NOT NULL,
    CONSTRAINT uq_role_chan UNIQUE (role_id, channel_id)
)
