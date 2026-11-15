-- Latest-bucket-per-device lookups (device snapshots) were a scan of every
-- second-resolution row for devices with no recent traffic.
CREATE INDEX flow_rollups_device_latest_idx ON flow_rollups(device_id, resolution, bucket DESC);
UPDATE install_state SET schema_version=31 WHERE singleton=1 AND schema_version<31;
