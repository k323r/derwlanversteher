import multiprocessing
import os.path
import sqlite3
import sys
import time

from conf import DIR_DATA

"""
TODO:
    provide USAGE information
"""

# Signal for end of transmission from the producer to the consumer.
SENTINEL = None

# Wait some time in the consumer loop to avoid hammering the cpu.
TIMEOUT = 1

SQL = {
    'insert_mac_addresses': """
        INSERT OR IGNORE INTO mac_addresses (
            mac_address,
            id_mac_address)
        VALUES (?, ?)""",
    'insert_packets': """
        INSERT OR IGNORE INTO packets (
            id_mac_address,
            time_stamp,
            packet_type,
            packet_subtype,
            rssi) 
        VALUES (?, ?, ?, ?, ?)""",
}

def produce(queue):
    """
    Enqueue each new line from stdin as it appears. When there is no more
    input, signal end of transmission to the consumer.
    """
    for line in sys.stdin:
        queue.put(line)
    queue.put(SENTINEL)

def mac_to_int(mac_address):
    return int(mac_address.replace(':', ''), 16)

def int_to_mac(id_mac_address):
    """
    TODO: Sanity check. Test correctnes.
    """
    r = hex(id_mac_address)[2:]
    return ':'.join([
        a + b
        for a, b in zip(
            [x for i, x in enumerate(r) if i % 2 == 1],
            [y for j, y in enumerate(r) if j % 2 == 0]
        )
    ])

def process_line(line):
    mac_address, rssi, time_stamp, packet_type, packet_subtype = line.split(',')
    id_mac_address = mac_to_int(mac_address)
    return (
        mac_address, id_mac_address, time_stamp, packet_type,
        packet_subtype, rssi)

class DatabaseImporter(object):
    
    def __init__(self, database_path):
        self.database_path = database_path

    def insert_into_database(self, lines):
        """
        If lines are nonempty, extract mac_addresses and packets, insert
        mac_addresses then packets into the database.
        """
        if lines:
            processed_lines = [process_line(line) for line in lines]
            mac_addresses = [l[:2] for l in processed_lines]
            packets = [l[1:] for l in processed_lines]
            db_connection = sqlite3.connect(self.database_path)
            db_connection.executemany(SQL['insert_mac_addresses'], mac_addresses)
            db_connection.commit()
            db_connection.executemany(SQL['insert_packets'], packets)
            db_connection.commit()
            db_connection.close()

    def consume(self, queue):
        """
        Dequeue all items into a new list. Insert the list into the database.
        Repeat (after a while, to avoid hammering the cpu), unless the
        produceer has sent the SENTINEL.
        Note: We assume that the producer is much slower than the consumer.
        """
        while True:
            lines = []
            while not queue.empty():
                lines.append(queue.get())
            if SENTINEL == lines[-1]:
                self.insert_into_database(lines[:-1])
                break
            self.insert_into_database(lines)
            time.sleep(TIMEOUT)

if __name__ == '__main__':

    # We assume that the database exists already.
    # TODO: print USAGE if sys.argv[1] fails
    database_name = sys.argv[1]
    database_path = os.path.join(DIR_DATA, database_name)

    di = DatabaseImporter(database_path)

    # Run consumer process with empty queue, then start producing events.
    queue = multiprocessing.Queue()
    consumer_process = multiprocessing.Process(target=di.consume, args=(queue,))
    consumer_process.start()
    produce(queue)

    # When the producer has finished, i.e. the SENTINEL is on the queue, wait
    # for the consumer process to finish.
    consumer_process.join()