-------------------------------------------------------------------------------
--  TODO:
--      test correctness
--      compare memory footprint to plain text logging
-------------------------------------------------------------------------------

CREATE TABLE packet_types (
    -- static descriptions of packet types
    -- https://supportforums.cisco.com/document/52391/80211-frames-starter-guide-learn-wireless-sniffer-traces
    packet_type INTEGER CHECK (packet_type BETWEEN 0 and 2),
    packet_type_description TEXT UNIQUE NOT NULL,

    PRIMARY KEY (packet_type)
);

CREATE TABLE packet_subtypes (
    -- static descriptions of packet subtypes
    -- https://supportforums.cisco.com/document/52391/80211-frames-starter-guide-learn-wireless-sniffer-traces
    packet_type INTEGER NOT NULL,
    packet_subtype INTEGER NOT NULL CHECK (packet_subtype >= 0),
    packet_subtype_description TEXT UNIQUE NOT NULL,

    PRIMARY KEY (packet_type, packet_subtype),
    FOREIGN KEY (packet_type)
        REFERENCES packet_types (packet_type)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE TABLE mac_addresses (
    -- just a bijection to save some space in tables referencing mac addresses
    -- TODO: Does this really save space?
    id_logging_device INTEGER NOT NULL CHECK (id_logging_device > 0),
    id_mac_address INTEGER NOT NULL CHECK (id_mac_address > 0),
    mac_address TEXT NOT NULL,

    PRIMARY KEY (id_logging_device, id_mac_address)
);

CREATE TABLE packets (
    id_logging_device INTEGER NOT NULL,
    id_mac_address INTEGER NOT NULL,
    time_stamp REAL NOT NULL,
    packet_type INTEGER NOT NULL,
    packet_subtype INTEGER NOT NULL,
    rssi INTEGER NOT NULL,

    PRIMARY KEY (
        id_logging_device, id_mac_address, time_stamp, packet_type,
        packet_subtype),
    FOREIGN KEY (id_logging_device, id_mac_address)
        REFERENCES mac_addresses (id_logging_device, id_mac_address)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    FOREIGN KEY (packet_type, packet_subtype) 
        REFERENCES packet_subtypes (packet_type, packet_subtype)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE TABLE locations (
    latitude REAL NOT NULL CHECK (latitude BETWEEN -90.0 AND 90.0),
    longitude REAL NOT NULL CHECK (longitude BETWEEN -180.0 AND 180.0),
    time_stamp_start REAL NOT NULL,
    time_stamp_end REAL NOT NULL CHECK (time_stamp_start <= time_stamp_end),

    PRIMARY KEY (latitude, longitude, time_stamp_start, time_stamp_end)
);

CREATE VIEW packet_type_descriptions AS
    SELECT
        packet_type,
        packet_subtype,
        packet_type_description,
        packet_subtype_description
    FROM
        packet_types
        JOIN packet_subtypes USING (packet_type)
;

CREATE VIEW packets_by_locations AS
    SELECT
        mac_address,
        time_stamp,
        packet_type,
        packet_subtype,
        rssi,
        packet_type_description,
        packet_subtype_description,
        latitude,
        longitude
    FROM
        mac_addresses
        JOIN packets USING (id_logging_device, id_mac_address)
        JOIN packet_type_descriptions USING (packet_type, packet_subtype)
        JOIN locations ON
            time_stamp_start <= time_stamp
            AND time_stamp <= time_stamp_end
;
