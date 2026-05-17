CREATE TABLE IF NOT EXISTS rbac_role (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(1024)
);

CREATE TABLE IF NOT EXISTS rbac_role_permission (
    id          SERIAL PRIMARY KEY,
    role_id     INTEGER NOT NULL REFERENCES rbac_role(id) ON DELETE CASCADE,
    permission  VARCHAR(255) NOT NULL,
    UNIQUE (role_id, permission)
);

CREATE TABLE IF NOT EXISTS rbac_user_role (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL UNIQUE,
    role_id     INTEGER NOT NULL REFERENCES rbac_role(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rbac_role_channel (
    id          SERIAL PRIMARY KEY,
    role_id     INTEGER NOT NULL REFERENCES rbac_role(id) ON DELETE CASCADE,
    channel_id  CHAR(36) NOT NULL,
    UNIQUE (role_id, channel_id)
);
