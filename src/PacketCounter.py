
class PacketCounter:

    def __init__(self):
        self.packet_count_total = 0
        self.packet_count_preprocessed = 0
        self.start_time = 0

    def get_packet_count_total(self):
        return self.packet_count_total

    def get_packet_count_preprocessed(self):
        return self.packet_count_preprocessed

    def set_start_time(self, time):
        self.start_time = time

    def get_start_time(self):
        return self.start_time