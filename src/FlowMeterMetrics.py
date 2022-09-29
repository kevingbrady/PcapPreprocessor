from src.flow_meter_features.context.packet_direction import PacketDirection
from src.flow_meter_features.context.packet_flow_key import get_packet_flow_key
from src.improved_flow import Flow
from scapy.layers.inet import TCP

EXPIRED_UPDATE = 40
GARBAGE_COLLECT_PACKETS = 10000


class FlowMeterMetrics:

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.packet_count_total = 0
        self.output_mode = ''

    def process_packet(self, packet):

        direction = PacketDirection.FORWARD

        packet_flow_key = get_packet_flow_key(packet, direction)
        flow = self.flows.get(packet_flow_key)

        self.packet_count_total += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get(packet_flow_key)

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = Flow(packet, direction)
            packet_flow_key = get_packet_flow_key(packet, direction)
            self.flows[packet_flow_key] = flow

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            flow = Flow(packet, direction)
            self.flows[packet_flow_key] = flow

        elif (TCP in packet) and ("F" in str(packet[TCP].flags)):
            # If it has FIN flag then early collect flow and continue
            self.garbage_collect(packet.time)
            return flow, direction

        if self.packet_count_total % GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120 and self.output_mode == "flow"
        ):
            self.garbage_collect(packet.time)

        #print(packet_flow_key, flow.dest_ip, flow.src_ip, flow.src_port, flow.dest_port, flow.packet_length.data[None])

        return [flow, direction]

    def garbage_collect(self, latest_time) -> None:

        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)

            if (
                latest_time is None
                or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                or flow.duration > 90
            ):

                del self.flows[k]


