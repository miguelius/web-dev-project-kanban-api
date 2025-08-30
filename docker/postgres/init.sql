CREATE EXTENSION pgcrypto;

CREATE OR REPLACE FUNCTION generate_uid(size INT) RETURNS TEXT AS $$
DECLARE
  characters TEXT := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  bytes BYTEA := gen_random_bytes(size);
  l INT := length(characters);
  i INT := 0;
  output TEXT := '';
BEGIN
  WHILE i < size LOOP
    output := output || substr(characters, get_byte(bytes, i) % l + 1, 1);
    i := i + 1;
  END LOOP;
  RETURN output;
END;
$$ LANGUAGE plpgsql VOLATILE;

CREATE TABLE projects (name TEXT NOT NULL, repo_url TEXT, site_url TEXT, description TEXT, dependencies TEXT[], dev_dependencies TEXT[], status TEXT NOT NULL CHECK (status IN ('backlog', 'developing', 'done')), user_id TEXT NOT NULL, xata_id TEXT DEFAULT generate_uid(10) );
CREATE TABLE users (username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, xata_id TEXT DEFAULT generate_uid(10));
