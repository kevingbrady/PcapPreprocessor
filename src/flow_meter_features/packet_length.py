from .stats import Statistics
from src.flow_meter_features.context.packet_direction import PacketDirection


class PacketLength(Statistics):

    def __init__(self) -> None:
        self.packet_lengths = {
            None: 0,
            PacketDirection.FORWARD: 0,
            PacketDirection.REVERSE: 0
        }
        super().__init__()

    def process_packet(self, packet, direction=None) -> None:

        packet_length = len(packet)

        self.packet_lengths[direction] = packet_length
        self.packet_lengths[None] = packet_length
        self.calculate_statistics(packet_length, direction)

