CREATE TABLE rbac_role (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(1024)
)

CREATE TABLE rbac_role_permission (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_id     INTEGER NOT NULL REFERENCES rbac_role(id) ON DELETE CASCADE,
    permission  VARCHAR(255) NOT NULL,
    UNIQUE (role_id, permission)
)

CREATE TABLE rbac_user_role (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     INTEGER NOT NULL UNIQUE,
    role_id     INTEGER NOT NULL REFERENCES rbac_role(id) ON DELETE CASCADE
)

CREATE TABLE rbac_role_channel (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_id     INTEGER NOT NULL REFERENCES rbac_role(id) ON DELETE CASCADE,
    channel_id  CHAR(36) NOT NULL,
    UNIQUE (role_id, channel_id)
)
