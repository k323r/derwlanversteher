-------------------------------------------------------------------------------
-- Complete list of packet types and subtypes courtesy of:
-- https://supportforums.cisco.com/document/52391/80211-frames-starter-guide-learn-wireless-sniffer-traces
-- Note: Subtype gaps (e.g. (0,6), (0,7)) seem to be intentional.
-- TODO: Please, somebody review this code.
-------------------------------------------------------------------------------

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
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 2, 'reassociation_request');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 3, 'reassociation_response');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 4, 'probe_request');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 5, 'probe_response');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 8, 'beacon');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 9, 'atim');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 10, 'disassociation');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 11, 'authentication');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 12, 'deauthentication');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (0, 13, 'action');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (1, 8, 'block_ack_request');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (1, 9, 'block_ack');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (1, 10, 'ps_poll');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (1, 11, 'rts');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (1, 12, 'cts');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (1, 13, 'ack');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (1, 14, 'cf_end');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (1, 15, 'cf_end_cf_ack');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 0, 'data');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 1, 'data_cf_ack');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 2, 'data_cf_poll');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 3, 'data_cf_ack_cf_poll');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 4, 'null');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 5, 'cf_ack');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 6, 'cf_poll');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 7, 'cf_ack_cf_poll');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 8, 'qos_data');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 9, 'qos_data_cf_ack');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 10, 'qos_data_cf_poll');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 11, 'qos_data_cf_ack_cf_poll');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 12, 'qos_null');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 14, 'qos_cf_poll_no_data');
INSERT INTO packet_subtypes (packet_type, packet_subtype, packet_subtype_description) 
    VALUES (2, 15, 'qos_cf_ack_no_data');
