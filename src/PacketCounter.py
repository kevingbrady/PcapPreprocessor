
class PacketCounter:

    def __init__(self):
        self.count = 0
        self.start_time = 0

    def increment(self):
        self.count += 1

    def get_packet_count(self):
        return self.count

    def set_start_time(self, time):
        self.start_time = time

    def get_start_time(self):
        return self.start_time