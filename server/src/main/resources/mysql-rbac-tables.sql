CREATE TABLE IF NOT EXISTS rbac_role (
    id          INTEGER PRIMARY KEY AUTO_INCREMENT,
    name        VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(1024)
);

CREATE TABLE IF NOT EXISTS rbac_role_permission (
    id          INTEGER PRIMARY KEY AUTO_INCREMENT,
    role_id     INTEGER NOT NULL,
    permission  VARCHAR(255) NOT NULL,
    FOREIGN KEY (role_id) REFERENCES rbac_role(id) ON DELETE CASCADE,
    UNIQUE (role_id, permission)
);

CREATE TABLE IF NOT EXISTS rbac_user_role (
    id          INTEGER PRIMARY KEY AUTO_INCREMENT,
    user_id     INTEGER NOT NULL UNIQUE,
    role_id     INTEGER NOT NULL,
    FOREIGN KEY (role_id) REFERENCES rbac_role(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rbac_role_channel (
    id          INTEGER PRIMARY KEY AUTO_INCREMENT,
    role_id     INTEGER NOT NULL,
    channel_id  CHAR(36) NOT NULL,
    FOREIGN KEY (role_id) REFERENCES rbac_role(id) ON DELETE CASCADE,
    UNIQUE (role_id, channel_id)
);
