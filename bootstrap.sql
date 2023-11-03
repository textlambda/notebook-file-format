CREATE TABLE IF NOT EXISTS peek (
  id INTEGER NOT NULL PRIMARY KEY DEFAULT 1,
  value BLOB NOT NULL,
  meta TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entry (
  id TEXT NOT NULL PRIMARY KEY,
  parent_id TEXT NOT NULL,
  encrypted_name BLOB NOT NULL,
  encrypted_value BLOB,
  deleted INTEGER NOT NULL DEFAULT 0,
  hash BLOB NOT NULL,
  synced_hash BLOB,
  server_tid INTEGER NOT NULL DEFAULT 0,
  modified TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (id != parent_id),
  CHECK (deleted IN (0, 1))
);

CREATE TABLE IF NOT EXISTS entry_history (
  id INTEGER PRIMARY KEY,
  entry_id TEXT NOT NULL,
  encrypted_value BLOB,
  modified TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS trigger_entry_history_on_update
BEFORE UPDATE OF encrypted_value, deleted ON entry
FOR EACH ROW
BEGIN
  INSERT INTO entry_history (entry_id, encrypted_value, modified)
  VALUES (OLD.id, OLD.encrypted_value, OLD.modified);

  DELETE FROM entry_history WHERE
    entry_id=NEW.id AND
    (encrypted_value IS NULL OR
     NEW.deleted=1 OR
     id NOT IN (
      SELECT
        id
      FROM
        entry_history
      WHERE
        entry_id=NEW.id
      ORDER BY
        modified DESC
      LIMIT
        100
    ));
END
;

CREATE TABLE IF NOT EXISTS entry_conflict (
  id TEXT NOT NULL PRIMARY KEY,
  parent_id TEXT NOT NULL,
  encrypted_name BLOB NOT NULL,
  encrypted_value BLOB,
  deleted INTEGER NOT NULL,
  hash BLOB NOT NULL,
  synced_hash BLOB,
  server_tid INTEGER NOT NULL,
  modified TEXT NOT NULL,
  CHECK (id != parent_id),
  CHECK (deleted IN (0, 1))
);

CREATE TABLE IF NOT EXISTS meta (
  name TEXT NOT NULL PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entry_history_entry_id ON entry_history(entry_id);
CREATE INDEX IF NOT EXISTS idx_entry_parent_id ON entry(parent_id);
CREATE INDEX IF NOT EXISTS idx_entry_out_of_sync ON entry(hash, synced_hash)
  WHERE synced_hash IS NULL OR hash != synced_hash;

CREATE TRIGGER IF NOT EXISTS trigger_entry_on_update
BEFORE UPDATE OF parent_id, encrypted_name, encrypted_value, deleted ON entry
FOR EACH ROW
BEGIN
  UPDATE entry
    SET modified = CURRENT_TIMESTAMP
  WHERE id=NEW.id;
END;
