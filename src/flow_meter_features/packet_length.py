from .stats import Statistics
from src.flow_meter_features.context.packet_direction import PacketDirection


class PacketLength(Statistics):

    def __init__(self) -> None:
        super().__init__()
        self.packet_length = 0

    def process_packet(self, packet, direction=None) -> None:

        self.packet_length = len(packet)
        self.calculate_statistics(self.packet_length)

