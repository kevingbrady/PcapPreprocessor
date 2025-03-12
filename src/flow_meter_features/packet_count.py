from src.flow_meter_features.context.packet_direction import PacketDirection
from scapy.packet import Raw, NoPayload


class PacketCount:
    """This class extracts features related to the Packet Count."""

    def __init__(self) -> None:
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

    def process_packet(self, packet, direction) -> None:
        self.packet_count[None]['count'] += 1
        self.packet_count[direction]['count'] += 1

        self.set_payload_count(packet)
        self.set_payload_count(packet, direction)

    def get_total(self, direction=None) -> int:

        return self.packet_count[direction]['count']

    def get_rate(self, duration, direction=None) -> float:

        if duration > 1:
            return self.get_total(direction) / duration

        return 0.0

    def get_down_up_ratio(self) -> float:

        """Calculates download and upload ratio.

        Returns:
            float: down/up ratio
        """
        forward_size = self.get_total(PacketDirection.FORWARD)
        backward_size = self.get_total(PacketDirection.REVERSE)
        if forward_size > 1:
            return backward_size / forward_size
        return 0.0

    def get_payload_count(self, direction=None) -> int:

        return self.packet_count[direction]['payload']

    @staticmethod
    def get_payload(packet) -> Raw | NoPayload:
        if 'TCP' in packet:
            return packet['TCP'].payload
        if 'UDP' in packet:
            return packet['UDP'].payload

    def set_payload_count(self, packet, direction=None) -> None:
        if len(self.get_payload(packet)) > 0:
            self.packet_count[direction]['payload'] += 1
