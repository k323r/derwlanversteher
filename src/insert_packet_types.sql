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
