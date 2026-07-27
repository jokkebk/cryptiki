CREATE TABLE legacy_capsules (
  lookup_id TEXT PRIMARY KEY,
  format INTEGER NOT NULL CHECK (format IN (1, 2)),
  blob BLOB NOT NULL,
  created INTEGER NOT NULL,
  expires INTEGER NOT NULL
);

CREATE INDEX legacy_capsules_expires ON legacy_capsules (expires);
