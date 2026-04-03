from enum import Enum
from typing import *
from src.flow_meter_features.context.packet_direction import PacketDirection
from src.improved_flow import Flow
from src.flow_meter_features.constants import EXPIRED_UPDATE, GARBAGE_COLLECT_PACKETS
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class FlowKey:
    source: tuple[int, str]
    destination: tuple[int, str]
    source_port: int
    destination_port: int

    def __iter__(self):
        yield self.source
        yield self.destination
        yield self.source_port
        yield self.destination_port

    def __eq__(self, other):
        if not isinstance(other, FlowKey):
            return NotImplemented
        return (self.source, self.destination, self.source_port, self.destination_port) == (
            other.source, other.destination, other.source_port, other.destination_port)

    def __hash__(self):
        return hash((self.source, self.destination, self.source_port, self.destination_port))


class FlowMeterMetrics:

    def __init__(self, *args, **kwargs) -> None:
        self.flows = OrderedDict()
        self.node_ids = {}
        self.packet_count_total = 0
        self.output_mode = ''

    def get_packet_flow_key(self, packet: Any, direction: PacketDirection) -> FlowKey:

        src_ip, dst_ip, src_port, dst_port = self.get_flow_address_info(packet, direction)

        if src_ip not in self.node_ids.keys():
            self.node_ids.update({src_ip: len(self.node_ids)})

        if dst_ip not in self.node_ids.keys():
            self.node_ids.update({dst_ip: len(self.node_ids)})

        return FlowKey((self.node_ids[src_ip], src_ip), (self.node_ids[dst_ip], dst_ip), src_port, dst_port)

    @staticmethod
    def get_flow_address_info(packet: Any, direction: PacketDirection) -> tuple[str, str, int, int]:

        ip = 'IPv6' if 'IPv6' in packet else 'IP'

        if 'TCP' in packet:
            protocol = 'TCP'
        elif 'UDP' in packet:
            protocol = 'UDP'
        else:
            raise Exception("Only TCP protocols are supported.")

        if direction == PacketDirection.FORWARD:

            dst_ip = packet[ip].dst
            src_ip = packet[ip].src
            src_port = packet[protocol].sport
            dst_port = packet[protocol].dport
        else:

            dst_ip = packet[ip].src
            src_ip = packet[ip].dst
            src_port = packet[protocol].dport
            dst_port = packet[protocol].sport

        return src_ip, dst_ip, src_port, dst_port

    def process_packet(self, packet: Any) -> tuple[Flow, PacketDirection]:

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
                flow = Flow(packet_flow_key)
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

        self.garbage_collect(packet.time)

        return flow, direction

    def get_flows_as_list(self, last_packet_timestamp=-1, time_step=-1) -> list[float]:

        if last_packet_timestamp!= -1 and time_step != -1:
            # Uncomment if you want the flow list represented as a sparse matrix with only the most recent flow's data listed
            flow_list = []
            
            for flow in self.flows.values():
                #print(last_packet_timestamp - flow.packet_time.get_latest_timestamp(), time_step)
                if last_packet_timestamp - flow.packet_time.get_latest_timestamp() <= time_step:
                    flow_list.append(flow.get_data_as_list())
                else:
                    flow_list.append([0] * (flow.num_features - 4))  # Don't include src_ip, dst_ip, src_node_id, or dst_node_id
            

            #print(*flow_list, end='\n\n')
            return flow_list

        else:
            return [flow.get_data_as_list() for flow in self.flows.values()]

    def garbage_collect(self, latest_time) -> None:

        self.flows = {key: flow for key, flow in self.flows.items() if
                      not flow.update_flow_duration(latest_time)}
