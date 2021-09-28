from .stats import Statistics


class PacketLength(Statistics):

    def __init__(self):

        super().__init__()

    def process_packet(self, packet, direction=None):

        self.data[None]['count'] += 1
        self.data[direction]['count'] += 1

        packet_length = len(packet)

        self.calculate_statistics(packet_length, direction)

