from datetime import datetime
from src.flow_meter_features.context.packet_direction import PacketDirection
from .stats import Statistics


class PacketTime(Statistics):
    """This class extracts features related to the Packet Times."""

    def __init__(self):
        self.timestamps = {
            'first_timestamp': 0,
            'last_timestamp': 0,
            PacketDirection.FORWARD: 0,
            PacketDirection.REVERSE: 0,
        }

        super().__init__()

    def process_packet(self, packet, direction):

        self.data[None]['count'] += 1
        self.data[direction]['count'] += 1

        if self.timestamps['first_timestamp'] == 0:
            self.timestamps['first_timestamp'] = packet.time

        self.timestamps['last_timestamp'] = packet.time
        iat = self.get_packet_iat(packet, direction)

        self.calculate_statistics(iat, direction)

    def get_packet_iat(self, packet, packet_direction=None):

        if self.timestamps[packet_direction] == 0:
            self.timestamps[packet_direction] = packet.time
            return 0

        inter_arrival_time = 1e6 * float(packet.time - self.timestamps[packet_direction])
        self.timestamps[packet_direction] = packet.time
        return inter_arrival_time

    def get_timestamp(self):
        return self.timestamps['last_timestamp']

    def get_datetime(self):
        """Returns the date and time in a human readeable format.

                Return (str):
                    String of Date and time.

                """
        date_time = datetime.fromtimestamp(self.timestamps['last_timestamp']).strftime("%Y-%m-%d %H:%M:%S")
        return date_time

    def get_duration(self):

        return self.timestamps['last_timestamp'] - self.timestamps['first_timestamp']
