-- Owner approval of exactly one host per camera. A camera is only ever
-- contacted (ONVIF, RTSP) at the single IPv4 address stored here, and only
-- through the named local interface. The row is the durable record of that
-- approval: the in-memory target registry is rebuilt from it at startup and
-- every session re-checks the address against the live interface inventory,
-- so a row that no longer matches the network is refused, not trusted.
--
-- `interface` is the local interface name the address was approved on.
-- `address` is an IPv4 literal (never a hostname, so there is no DNS to
-- rebind). `name` is the owner's optional label for the camera.
CREATE TABLE camera_targets (
    camera_id TEXT PRIMARY KEY NOT NULL
        REFERENCES cameras(camera_id) ON DELETE CASCADE,
    interface TEXT NOT NULL CHECK(length(interface) BETWEEN 1 AND 256),
    address TEXT NOT NULL
        CHECK(length(address) BETWEEN 7 AND 15)
        CHECK(address NOT GLOB '*[^0-9.]*'),
    onvif_port INTEGER NOT NULL CHECK(onvif_port BETWEEN 1 AND 65535),
    rtsp_port INTEGER NOT NULL CHECK(rtsp_port BETWEEN 1 AND 65535),
    allow_basic INTEGER NOT NULL DEFAULT 0 CHECK(allow_basic IN (0, 1)),
    approved_at TEXT NOT NULL CHECK(length(approved_at) BETWEEN 20 AND 40),
    name TEXT CHECK(name IS NULL OR length(name) BETWEEN 1 AND 64),
    UNIQUE(address)
);

UPDATE install_state SET schema_version = 41 WHERE singleton = 1 AND schema_version < 41;
