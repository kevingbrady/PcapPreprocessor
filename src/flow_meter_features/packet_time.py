from datetime import datetime
from src.flow_meter_features.context.packet_direction import PacketDirection
from .stats import Statistics


class PacketTime(Statistics):
    """This class extracts features related to the Packet Times."""

    def __init__(self):
        self.timestamps = {
            None: {
                'first_timestamp': 0,
                'last_timestamp': 0,
            },
            PacketDirection.FORWARD: {
                'first_timestamp': 0,
                'last_timestamp': 0,
            },
            PacketDirection.REVERSE: {
                'first_timestamp': 0,
                'last_timestamp': 0,
            },
        }

        super().__init__()

    def process_packet(self, packet, direction):

        if self.timestamps[None]['first_timestamp'] == 0:
            self.timestamps[None]['first_timestamp'] = packet.time

        if self.timestamps[direction]['first_timestamp'] == 0:
            self.timestamps[direction]['first_timestamp'] = packet.time

        iat = self.get_packet_iat(packet, direction)

        self.timestamps[None]['last_timestamp'] = packet.time
        self.timestamps[direction]['last_timestamp'] = packet.time

        self.calculate_statistics(iat, direction)

    def get_packet_iat(self, packet, packet_direction=None):

        inter_arrival_time = 1e3 * float(packet.time - self.timestamps[packet_direction]['last_timestamp'])
        return inter_arrival_time
