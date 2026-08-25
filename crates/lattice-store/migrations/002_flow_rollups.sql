CREATE TABLE flow_rollups (
 resolution TEXT NOT NULL CHECK(resolution IN ('second','minute','hour')),
 bucket TEXT NOT NULL,
 device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
 protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp','icmp','other')),
 destination TEXT NOT NULL CHECK(destination IN ('local','lan','internet','unknown')),
 interface INTEGER NOT NULL CHECK(interface>0),
 metadata_ip TEXT NOT NULL DEFAULT '',
 metadata_domain TEXT NOT NULL DEFAULT '',
 upload INTEGER NOT NULL CHECK(upload>=0), download INTEGER NOT NULL CHECK(download>=0),
 coverage TEXT NOT NULL CHECK(coverage IN ('complete','router-reported','local-only','estimated')),
 updated_at TEXT NOT NULL,
 PRIMARY KEY(resolution,bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain)
);
CREATE INDEX flow_rollups_range_idx ON flow_rollups(resolution,bucket,device_id);
CREATE TABLE flow_compaction_seals (
 child_resolution TEXT NOT NULL CHECK(child_resolution IN ('second','minute')),
 parent_bucket TEXT NOT NULL, device_id TEXT NOT NULL, protocol TEXT NOT NULL,
 destination TEXT NOT NULL, interface INTEGER NOT NULL, metadata_ip TEXT NOT NULL,
 metadata_domain TEXT NOT NULL,
 PRIMARY KEY(child_resolution,parent_bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain)
);
CREATE VIEW protocol_rollups AS SELECT resolution,bucket,device_id,protocol,SUM(upload) upload,SUM(download) download,
 CASE WHEN MIN(coverage)=MAX(coverage) THEN MIN(coverage) ELSE 'estimated' END coverage
 FROM flow_rollups GROUP BY resolution,bucket,device_id,protocol;
UPDATE install_state SET schema_version=2 WHERE singleton=1 AND schema_version<2;
