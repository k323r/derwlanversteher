-- create database:
-- rm -f data/test.db && cat src/schema.sql | sqlite3 data/test.db

CREATE TABLE packet_types(
    packet_type INTEGER NOT NULL PRIMARY KEY,
    packet_type_description TEXT NOT NULL
);

CREATE TABLE packet_subtypes (
    packet_type INTEGER NOT NULL
        REFERENCES packet_types(packet_type)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    packet_subtype INTEGER NOT NULL,
    packet_subtype_description TEXT NOT NULL,
    PRIMARY KEY (packet_type, packet_subtype)
);

CREATE TABLE packets (
    mac_address TEXT NOT NULL,
    time_stamp REAL NOT NULL,
    packet_type INTEGER NOT NULL,
    packet_subtype INTEGER NOT NULL,
    rssi INTEGER NOT NULL,
    PRIMARY KEY (mac_address, time_stamp, packet_type, packet_subtype),
    FOREIGN KEY (packet_type, packet_subtype) 
        REFERENCES packet_subtypes (packet_type, packet_subtype)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE TABLE locations (
    latitude REAL NOT NULL CHECK(latitude BETWEEN -90.0 AND 90.0),
    longitude REAL NOT NULL CHECK(longitude BETWEEN -180.0 AND 180.0),
    time_stamp_start REAL NOT NULL,
    time_stamp_end REAL NOT NULL CHECK(time_stamp_start <= time_stamp_end),
    PRIMARY KEY (latitude, longitude, time_stamp_start, time_stamp_end)
);


INSERT INTO packet_types (packet_type, packet_type_description) 
    VALUES (0, 'management');
INSERT INTO packet_types (packet_type, packet_type_description) 
    VALUES (1, 'control');
INSERT INTO packet_types (packet_type, packet_type_description) 
    VALUES (2, 'data');

INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 0, 'association_request');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 1, 'association_response');
-- [...]
-- TODO: complete the list of subtypes as in
-- https://supportforums.cisco.com/document/52391/80211-frames-starter-guide-learn-wireless-sniffer-traces
