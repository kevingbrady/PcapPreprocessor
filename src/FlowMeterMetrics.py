from src.flow_meter_features.context.packet_direction import PacketDirection
from src.improved_flow import Flow
from src.flow_meter_features.constants import EXPIRED_UPDATE, GARBAGE_COLLECT_PACKETS
from collections import OrderedDict


class FlowMeterMetrics:

    def __init__(self, *args, **kwargs):
        self.flows = OrderedDict()
        self.node_ids = {}
        self.packet_count_total = 0
        self.output_mode = ''

    def get_packet_flow_key(self, packet, direction):

        packet_flow_info = Flow.get_flow_address_info(packet, direction)

        src_ip, dst_ip, src_port, dst_port = packet_flow_info

        if src_ip not in self.node_ids.keys():
            self.node_ids.update({src_ip: len(self.node_ids)})

        if dst_ip not in self.node_ids.keys():
            self.node_ids.update({dst_ip: len(self.node_ids)})

        return self.node_ids[src_ip], self.node_ids[dst_ip], int(src_port), int(dst_port)

    def process_packet(self, packet) -> (Flow, PacketDirection):

        self.packet_count_total += 1

        # Check flow in reverse direction
        direction = PacketDirection.REVERSE
        # packet_flow_key = Flow.get_packet_flow_key(packet, direction)

        packet_flow_key = self.get_packet_flow_key(packet, direction)

        flow = self.flows.get(packet_flow_key)

        if flow is None:
            # Check flow in forward direction
            direction = PacketDirection.FORWARD
            packet_flow_key = self.get_packet_flow_key(packet, direction)
            flow = self.flows.get(packet_flow_key)

            if flow is None:
                # If flow does not exist create new flow
                flow = Flow(packet, direction)
                self.flows[packet_flow_key] = flow

        if 'TCP' in packet:
            if "R" in str(packet['TCP'].flags):
                # If it has an RST flag then early collect flow and continue
                flow.completed = True
                self.garbage_collect(packet.time)

            if "A" in str(packet['TCP'].flags):
                if (flow.flag_count.flag_count('F', PacketDirection.FORWARD) >= 1
                        and flow.flag_count.flag_count('F', PacketDirection.REVERSE) >= 1):
                    flow.completed = True
                    self.garbage_collect(packet.time)

            flow.ack = packet['TCP'].ack
            flow.set_window_size(packet, direction)

        flow.get_protocol(packet)
        flow.active_idle.process_packet(packet, flow.packet_time.get_latest_timestamp(), direction)
        flow.packet_time.process_packet(packet, direction)
        flow.packet_count.process_packet(packet, direction)
        flow.packet_length.process_packet(packet, direction)
        flow.packet_bulk.update_flow_bulk(packet, direction)
        flow.flow_bytes.process_packet(packet, direction)
        flow.flag_count.process_packet(packet, direction)

        flow.flow_sort(packet.time)

        if (self.packet_count_total % GARBAGE_COLLECT_PACKETS) == 0:  # or flow.packet_time.get_flow_duration() > 120:
            self.garbage_collect(packet.time)

    def garbage_collect(self, latest_time) -> None:

        self.flows = {key: flow for key, flow in self.flows.items() if
                      (latest_time - flow.packet_time.get_latest_timestamp()) <= EXPIRED_UPDATE
                      and flow.completed is False}
