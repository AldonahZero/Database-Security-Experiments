CREATE TABLE IF NOT EXISTS items (
    item_id INTEGER PRIMARY KEY,
    stock INTEGER NOT NULL DEFAULT 100000,
    version INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS request_events (
    event_id BIGSERIAL PRIMARY KEY,
    item_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    payload TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_request_events_item_id
    ON request_events(item_id);

INSERT INTO items (item_id, stock, version)
SELECT gs, 100000, 0
FROM generate_series(1, 12000) AS gs
ON CONFLICT (item_id) DO NOTHING;

ANALYZE items;
ANALYZE request_events;
