from src.flow_meter_features.context.packet_direction import PacketDirection
from src.flow_meter_features.context.packet_flow_key import get_packet_flow_key
from src.improved_flow import Flow
from scapy.layers.inet import TCP
from collections import OrderedDict

EXPIRED_UPDATE = 120
GARBAGE_COLLECT_PACKETS = 480


class FlowMeterMetrics:

    def __init__(self, *args, **kwargs):
        self.flows = OrderedDict()
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

        if (packet.time - flow.packet_time.get_latest_timestamp()) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            flow = Flow(packet, direction)
            self.flows[packet_flow_key] = flow

        if packet.haslayer(TCP):
            if "R" in str(packet[TCP].flags):
                # If it has an RST flag then early collect flow and continue
                flow.completed = True
                self.garbage_collect(packet.time)

            if "A" in str(packet[TCP].flags):
                if flow.flag_count.flag_count('F', PacketDirection.FORWARD) >= 1 and flow.flag_count.flag_count('F', PacketDirection.REVERSE) >= 1:
                    flow.completed = True
                    self.garbage_collect(packet.time)

        flow.ack = 0
        if packet.haslayer('TCP'):
            flow.ack = packet['TCP'].fields['ack']

        flow.protocol = flow.get_protocol(packet)
        flow.set_window_size(packet, direction)
        flow.active_idle.process_packet(packet, flow.packet_time.get_latest_timestamp(), direction)
        flow.packet_time.process_packet(packet, direction)
        flow.packet_count.process_packet(packet, direction)
        flow.packet_length.process_packet(packet, direction)
        flow.packet_bulk.update_flow_bulk(packet, direction)
        flow.flow_bytes.process_packet(packet, direction)
        flow.flag_count.process_packet(packet, direction)

        if self.packet_count_total % GARBAGE_COLLECT_PACKETS == 0:
            self.garbage_collect(packet.time)

        #print(packet_flow_key, flow.dest_ip, flow.src_ip, flow.src_port, flow.dest_port, flow.packet_length.data[None])

        return flow, direction

    def garbage_collect(self, latest_time) -> None:

        for key, flow in self.flows.items():

            if latest_time - flow.packet_time.timestamps[None]["last_timestamp"] > EXPIRED_UPDATE:

                flow.completed = True

        self.flows = {key: flow for key, flow in self.flows.items() if flow.completed is False}


