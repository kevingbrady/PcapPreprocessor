
class PacketCounter:

    def __init__(self):
        self.packet_count_total = 0
        self.packet_count_preprocessed = 0

    def get_packet_count_total(self) -> int:
        return self.packet_count_total

    def get_packet_count_preprocessed(self) -> int:
        return self.packet_count_preprocessed
