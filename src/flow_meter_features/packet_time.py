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

    def process_packet(self, packet, direction) -> None:

        latest_time = packet.time

        if self.timestamps[None]['first_timestamp'] == 0:
            self.timestamps[None]['first_timestamp'] = latest_time

        if self.timestamps[direction]['first_timestamp'] == 0:
            self.timestamps[direction]['first_timestamp'] = latest_time

        if self.timestamps[direction]['last_timestamp'] > 0:
            iat = self.get_packet_iat(latest_time, direction)
            self.calculate_statistics(iat, direction)

        self.timestamps[None]['last_timestamp'] = latest_time
        self.timestamps[direction]['last_timestamp'] = latest_time

    def get_packet_iat(self, latest_time, direction=None) -> float:

        inter_arrival_time = 1e3 * float(latest_time - self.timestamps[direction]['last_timestamp'])
        return inter_arrival_time

    def get_latest_timestamp(self, direction=None) -> float:
        return self.timestamps[direction]["last_timestamp"]

    def get_first_timestamp(self, direction=None) -> float:
        return self.timestamps[direction]["first_timestamp"]

    def get_flow_duration(self, direction=None) -> float:
        if self.timestamps[direction]["first_timestamp"] > 0:
            return self.timestamps[direction]["last_timestamp"] - self.timestamps[direction]["first_timestamp"]
        return 0.0
