CREATE TABLE IF NOT EXISTS files (
    ino BIGSERIAL PRIMARY KEY,
    parent_ino BIGINT NOT NULL,
    token VARCHAR(255) NOT NULL,
    name TEXT NOT NULL,
    is_dir BOOLEAN NOT NULL,
    data BYTEA
);

CREATE INDEX IF NOT EXISTS idx_files_token_parent ON files (token, parent_ino);
CREATE INDEX IF NOT EXISTS idx_files_token_ino ON files (token, ino);
CREATE UNIQUE INDEX IF NOT EXISTS idx_files_token_parent_name ON files (token, parent_ino, name);
