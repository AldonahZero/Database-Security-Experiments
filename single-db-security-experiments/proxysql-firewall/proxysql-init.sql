CREATE TABLE IF NOT EXISTS vuln_users (
    id integer PRIMARY KEY,
    username text NOT NULL,
    secret text NOT NULL
);

INSERT INTO vuln_users (id, username, secret) VALUES
    (1, 'alice', 'secret-alice'),
    (2, 'bob', 'secret-bob'),
    (3, 'carol', 'secret-carol')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS call_marker (
    id integer PRIMARY KEY,
    value integer NOT NULL
);
INSERT INTO call_marker (id, value) VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS sensitive_marker (
    id integer PRIMARY KEY,
    value integer NOT NULL
);
INSERT INTO sensitive_marker (id, value) VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE PROCEDURE public.safe_proc(IN increment_by integer)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE call_marker SET value = value + increment_by WHERE id = 1;
END;
$$;

CREATE OR REPLACE PROCEDURE public.sensitive_proc(IN increment_by integer)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE sensitive_marker SET value = value + increment_by WHERE id = 1;
END;
$$;

CREATE OR REPLACE PROCEDURE public.safe_proc_audit(IN increment_by integer)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE call_marker SET value = value + increment_by WHERE id = 1;
END;
$$;

-- A legitimate hard-negative whose name shares a prefix with the sensitive
-- procedure.  It updates only the normal marker and is used to measure false
-- positives when the policy uses a broad procedure-name pattern.
CREATE OR REPLACE PROCEDURE public.sensitive_proc_audit(IN increment_by integer)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE call_marker SET value = value + increment_by WHERE id = 1;
END;
$$;
