from datetime import datetime
from src.flow_meter_features.context.packet_direction import PacketDirection
from .stats import Statistics


class PacketTime(Statistics):
    """This class extracts features related to the Packet Times."""

    def __init__(self) -> None:

        super().__init__()

        self.timestamps = {
                'first_timestamp': 0.0,
                'last_timestamp': 0.0,
            }

        self.iat = 0.0

    def process_packet(self, packet) -> None:

        packet_timestamp = float(packet.time)

        if self.timestamps['first_timestamp'] == 0.0:
            self.timestamps['first_timestamp'] = packet_timestamp

        if self.timestamps['last_timestamp'] > 0.0:
            self.iat = self.get_packet_iat(packet_timestamp)
            self.calculate_statistics(self.iat)

        self.timestamps['last_timestamp'] = packet_timestamp

    def get_packet_iat(self, latest_time) -> float:

        return 1e3 * float(latest_time - self.timestamps['last_timestamp'])

    def get_first_timestamp(self) -> float:
        return self.timestamps["first_timestamp"]

    def get_latest_timestamp(self) -> float:
        return self.timestamps["last_timestamp"]

    def get_flow_duration(self, latest_time) -> float:
        if self.timestamps["first_timestamp"] == 0.0:
            return 0.0
        return latest_time - self.timestamps["first_timestamp"]
