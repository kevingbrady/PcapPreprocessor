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

        self.duration = 0

    def process_packet(self, packet, direction):
        self.packet_count[None]['count'] += 1
        self.packet_count[direction]['count'] += 1

        self.has_payload(packet, None)
        self.has_payload(packet, direction)

    def get_total(self, direction=None) -> int:

        return self.packet_count[direction]['count']

    def get_rate(self, direction=None) -> float:

        if self.duration == 0:
            rate = 0
        else:
            rate = self.get_total(direction) / self.duration

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
        if "TCP" in packet:
            return packet["TCP"].payload
        elif "UDP" in packet:
            return packet["UDP"].payload
        return 0

    def has_payload(self, packet, direction=None):
        if len(self.get_payload(packet)) > 0:
            self.packet_count[direction]['payload'] += 1
