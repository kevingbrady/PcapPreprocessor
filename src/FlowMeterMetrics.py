from src.flow_meter_features.context.packet_direction import PacketDirection
from src.improved_flow import Flow
from src.flow_meter_features.constants import EXPIRED_UPDATE, GARBAGE_COLLECT_PACKETS
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class FlowKey:
    source_node_id: int
    destination_node_id: int
    source_port: int
    destination_port: int

    def __iter__(self):
        yield self.source_node_id
        yield self.destination_node_id
        yield self.source_port
        yield self.destination_port

    def __eq__(self, other):
        if not isinstance(other, FlowKey):
            return NotImplemented
        return (self.source_node_id, self.destination_node_id, self.source_port, self.destination_port) == (
            other.source_node_id, other.destination_node_id, other.source_port, other.destination_port)

    def __hash__(self):
        return hash((self.source_node_id, self.destination_node_id, self.source_port, self.destination_port))


class FlowMeterMetrics:

    def __init__(self, *args, **kwargs) -> None:
        self.flows = OrderedDict()
        self.node_ids = {}
        self.packet_count_total = 0
        self.output_mode = ''

    def get_packet_flow_key(self, packet, direction) -> FlowKey:

        src_ip, dst_ip, src_port, dst_port = Flow.get_flow_address_info(packet, direction)

        if src_ip not in self.node_ids.keys():
            self.node_ids.update({src_ip: len(self.node_ids)})

        if dst_ip not in self.node_ids.keys():
            self.node_ids.update({dst_ip: len(self.node_ids)})

        return FlowKey(self.node_ids[src_ip], self.node_ids[dst_ip], src_port, dst_port)

    def process_packet(self, packet) -> (Flow, PacketDirection):

        self.packet_count_total += 1

        # Check flow in reverse direction
        direction = PacketDirection.REVERSE
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
                # If it has an RST flag then flow is completed
                flow.completed = True

            if "A" in str(packet['TCP'].flags):
                if (flow.flag_count.flag_count('F', PacketDirection.FORWARD) >= 1
                        and flow.flag_count.flag_count('F', PacketDirection.REVERSE) >= 1):
                    flow.completed = True

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

        # if (self.packet_count_total % GARBAGE_COLLECT_PACKETS) == 0:  # or flow.packet_time.get_flow_duration() > 120:

        self.garbage_collect(packet.time)

        return flow, direction

    def get_flows_as_list(self, start_timestamp=-1, end_timestamp=-1):

        if start_timestamp != -1 and end_timestamp != -1:
            flow_list = []
            for flow in self.flows.values():
                #print(start_timestamp, t, end_timestamp)
                if start_timestamp <= flow.packet_time.get_latest_timestamp() <= end_timestamp:
                    flow_list.append(flow.get_data_as_list())
                else:

                    flow_list.append([0] * (flow.num_features - 2))  # Don't include src_ip or dst_ip

            #print(*flow_list, end='\n\n')
            return flow_list

        else:
            return [self.flows[key].get_data_as_list() for key in self.flows]

    def get_flow_index(self, flow_key):

        for idx, key in enumerate(self.flows.keys()):
            if key == flow_key:
                return idx
        return -1

    def completed_flows(self, latest_time) -> list:
        completed_flows = []

        for key, flow in self.flows.items():
            flow.update_flow_duration(latest_time)
            if flow.completed:
                completed_flows.append(key)

        return completed_flows

    def garbage_collect(self, latest_time) -> None:
        for key in self.completed_flows(latest_time):
            self.flows.pop(key)

        '''
        for key in self.completed_flows(latest_time):
            print(key)
            self.flows.pop(key)
    
        
        self.flows = {key: flow for key, flow in self.flows.items() if
                      (latest_time - flow.packet_time.get_latest_timestamp()) <= EXPIRED_UPDATE
                      and flow.completed is False}
        '''
