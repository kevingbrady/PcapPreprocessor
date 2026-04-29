from src.flow_meter_features.context.packet_direction import PacketDirection
from scapy.packet import Raw, NoPayload


class PacketCount:
    """This class extracts features related to the Packet Count."""

    def __init__(self) -> None:
        self.packet_count = {
                'count': 0,
                'payload': 0
            }

    def process_packet(self, packet) -> None:
        self.packet_count['count'] += 1

        self.set_payload_count(packet)

    def get_total(self) -> int:

        return self.packet_count['count']

    def get_rate(self, duration) -> float:

        if duration > 1:
            return self.get_total() / duration

        return 0.0

    def get_payload_count(self) -> int:

        return self.packet_count['payload']

    @staticmethod
    def get_payload(packet) -> Raw | NoPayload:
        if 'TCP' in packet:
            return packet['TCP'].payload
        if 'UDP' in packet:
            return packet['UDP'].payload

    def set_payload_count(self, packet) -> None:
        if len(self.get_payload(packet)) > 0:
            self.packet_count['payload'] += 1
