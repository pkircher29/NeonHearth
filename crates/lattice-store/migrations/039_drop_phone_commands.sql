-- Superseded by phone_command_replays (037), which stores the response as well
-- as the request fingerprint. 032_phone_commands.sql stays as a file because it
-- may already be applied; this retires its table.
DROP TABLE IF EXISTS phone_commands;

UPDATE install_state SET schema_version = 39 WHERE singleton = 1 AND schema_version < 39;
