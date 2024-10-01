from .stats import Statistics


class PacketLength(Statistics):

    def __init__(self):

        super().__init__()

    def process_packet(self, packet, direction=None):

        self.calculate_statistics(len(packet), direction)

