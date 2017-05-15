INSERT INTO mac_addresses (id_mac_address, mac_address)
    VALUES (1, 'F4:CB:52:9D:DB:3E');
INSERT INTO mac_addresses (id_mac_address, mac_address)
    VALUES (2, '5C:DC:96:6F:88:6C');

INSERT INTO packets (id_mac_address, time_stamp, packet_type, packet_subtype, rssi)
    VALUES (1, 1484436034.981551, 0, 0, -46);
INSERT INTO packets (id_mac_address, time_stamp, packet_type, packet_subtype, rssi)
    VALUES (2, 1485036034.981551, 0, 1, -77);

INSERT INTO locations (latitude, longitude, time_stamp_start, time_stamp_end)
    VALUES (-43.34252345, -102.73459, 1484435034.981551, 1484438034.981551);
INSERT INTO locations (latitude, longitude, time_stamp_start, time_stamp_end)
    VALUES (43.34252345, 102.73459, 1485016034.981551, 1485046034.981551);

