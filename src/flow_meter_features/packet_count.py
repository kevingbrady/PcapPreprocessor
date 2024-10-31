from src.flow_meter_features.context.packet_direction import PacketDirection


class PacketCount:
    """This class extracts features related to the Packet Count."""

    def __init__(self):
        self.packet_count = {
            None: {
                'count': 0,
                'payload': 0
            },
            PacketDirection.FORWARD: {
                'count': 0,
                'payload': 0
            },
            PacketDirection.REVERSE: {
                'count': 0,
                'payload': 0
            }
        }

    def process_packet(self, packet, direction):
        self.packet_count[None]['count'] += 1
        self.packet_count[direction]['count'] += 1

        self.set_payload_count(packet)
        self.set_payload_count(packet, direction)

    def get_total(self, direction=None) -> int:

        return self.packet_count[direction]['count']

    def get_rate(self, duration, direction=None) -> float:

        if duration == 0:
            rate = 0
        else:
            rate = self.get_total(direction) / duration

        return rate

    def get_down_up_ratio(self) -> float:

        """Calculates download and upload ratio.

        Returns:
            float: down/up ratio
        """
        forward_size = self.get_total(PacketDirection.FORWARD)
        backward_size = self.get_total(PacketDirection.REVERSE)
        if forward_size > 0:
            return backward_size / forward_size
        return 0

    def get_payload_count(self, direction=None):

        return self.packet_count[direction]['payload']

    @staticmethod
    def get_payload(packet):
        if 'TCP' in packet:
            return packet['TCP'].payload
        if 'UDP' in packet:
            return packet['UDP'].payload
        return 0

    def set_payload_count(self, packet, direction=None):
        if len(self.get_payload(packet)) > 0:
            self.packet_count[direction]['payload'] += 1
