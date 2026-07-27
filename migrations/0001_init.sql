CREATE TABLE vaults (
  id TEXT PRIMARY KEY,
  auth_hash BLOB NOT NULL,
  blob BLOB NOT NULL,
  rev INTEGER NOT NULL CHECK (rev >= 1),
  created INTEGER NOT NULL,
  modified INTEGER NOT NULL
);

CREATE TABLE revisions (
  id TEXT NOT NULL,
  rev INTEGER NOT NULL,
  blob BLOB NOT NULL,
  saved INTEGER NOT NULL,
  PRIMARY KEY (id, rev)
);

CREATE INDEX revisions_saved ON revisions (id, saved);
