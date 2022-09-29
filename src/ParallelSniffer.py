import sys

#sys.stderr = None  # suppress stderr
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

#sys.stderr = sys.__stderr__  # restore stderr

from src.PacketCounter import PacketCounter
from src.FlowMeterMetrics import FlowMeterMetrics
from src.clean_ip import _format_ip
import pandas as pd
import multiprocessing
import numpy as np
import csv

np.set_printoptions(linewidth=200000)


class Sniffer:

    keep_incomplete = False
    enable_cicflowmeter = False
    file_count = 0
    file_sizes = []

    def __init__(self, manager, keep_incomplete, enable_cicflowmeter, output_file, columns):

        self.total_packets = manager.Value('i', 0)
        self.completed = manager.list()
        self.in_progress = manager.list()
        self.lock = manager.Lock()
        self.index = manager.Value('i', 0)

        self.keep_incomplete = keep_incomplete
        self.enable_cicflowmeter = enable_cicflowmeter
        self.output_file = output_file
        self.columns = columns

    def run_sniffer(self, filename):

        self.in_progress.append(filename)
        self.display_progress()
        logging.info('Parsing file: ' + filename)

        target = 0

        if filename.lower().__contains__('attack'):
            target = 1

        packets = PcapReader(filename)
        counter = PacketCounter()
        packet_data = []

        flow_meter = FlowMeterMetrics(output_mode="flow")

        for pkt in packets:
            if counter.get_packet_count_total() == 0:
                counter.set_start_time(pkt.time)

            counter.packet_count_total += 1

            if self.enable_cicflowmeter:

                if (TCP in pkt) or (UDP in pkt):

                    flow, direction = flow_meter.process_packet(pkt)
                    flow_metrics = flow.get_data(pkt, direction)

                    packet_data.append([
                        flow_metrics["src_ip"],
                        flow_metrics["dst_ip"],
                        flow_metrics["src_port"],
                        flow_metrics["dst_port"],
                        flow_metrics["protocol"],
                        flow_metrics["pkt_length"],
                        flow_metrics["info"],
                        flow_metrics["timestamp"],
                        flow_metrics["flow_duration"],
                        flow_metrics["flow_byts_s"],
                        flow_metrics["flow_pkts_s"],
                        flow_metrics["fwd_pkts_s"],
                        flow_metrics["bwd_pkts_s"],
                        flow_metrics["tot_fwd_pkts"],
                        flow_metrics["tot_bwd_pkts"],
                        flow_metrics["totlen_fwd_pkts"],
                        flow_metrics["totlen_bwd_pkts"],
                        flow_metrics["fwd_pkt_len_max"],
                        flow_metrics["fwd_pkt_len_min"],
                        flow_metrics["fwd_pkt_len_mean"],
                        flow_metrics["fwd_pkt_len_std"],
                        flow_metrics["bwd_pkt_len_max"],
                        flow_metrics["bwd_pkt_len_min"],
                        flow_metrics["bwd_pkt_len_mean"],
                        flow_metrics["bwd_pkt_len_std"],
                        flow_metrics["pkt_len_max"],
                        flow_metrics["pkt_len_min"],
                        flow_metrics["pkt_len_mean"],
                        flow_metrics["pkt_len_std"],
                        flow_metrics["pkt_len_var"],
                        flow_metrics["fwd_header_len"],
                        flow_metrics["bwd_header_len"],
                        flow_metrics["fwd_seg_size_min"],
                        flow_metrics["fwd_act_data_pkts"],
                        flow_metrics["flow_iat_mean"],
                        flow_metrics["flow_iat_max"],
                        flow_metrics["flow_iat_min"],
                        flow_metrics["flow_iat_std"],
                        flow_metrics["fwd_iat_tot"],
                        flow_metrics["fwd_iat_max"],
                        flow_metrics["fwd_iat_min"],
                        flow_metrics["fwd_iat_mean"],
                        flow_metrics["fwd_iat_std"],
                        flow_metrics["bwd_iat_tot"],
                        flow_metrics["bwd_iat_max"],
                        flow_metrics["bwd_iat_min"],
                        flow_metrics["bwd_iat_mean"],
                        flow_metrics["bwd_iat_std"],
                        flow_metrics["fwd_psh_flags"],
                        flow_metrics["bwd_psh_flags"],
                        flow_metrics["fwd_urg_flags"],
                        flow_metrics["bwd_urg_flags"],
                        flow_metrics["fin_flag_cnt"],
                        flow_metrics["syn_flag_cnt"],
                        flow_metrics["rst_flag_cnt"],
                        flow_metrics["psh_flag_cnt"],
                        flow_metrics["ack_flag_cnt"],
                        flow_metrics["urg_flag_cnt"],
                        flow_metrics["ece_flag_cnt"],
                        flow_metrics["down_up_ratio"],
                        flow_metrics["pkt_size_avg"],
                        flow_metrics["init_fwd_win_byts"],
                        flow_metrics["init_bwd_win_byts"],
                        flow_metrics["active_max"],
                        flow_metrics["active_min"],
                        flow_metrics["active_mean"],
                        flow_metrics["active_std"],
                        flow_metrics["idle_max"],
                        flow_metrics["idle_min"],
                        flow_metrics["idle_mean"],
                        flow_metrics["idle_std"],
                        flow_metrics["fwd_byts_b_avg"],
                        flow_metrics["fwd_pkts_b_avg"],
                        flow_metrics["bwd_byts_b_avg"],
                        flow_metrics["bwd_pkts_b_avg"],
                        flow_metrics["fwd_blk_rate_avg"],
                        flow_metrics["bwd_blk_rate_avg"],
                        target
                    ])

                    # print(packet_data[-1])

            else:
                pkt.frame = counter.get_packet_count_preprocessed()
                time_elapsed = pkt.time - counter.get_start_time()
                pkt_length = pkt.wirelen
                ip_src = None
                ip_dst = None
                protocol = None
                info = 0  # ACK is only present in TCP packets

                if IP in pkt:
                    cleaned_ip_src = _format_ip(pkt[IP].src, "auto", "integer", "raise")
                    cleaned_ip_dst = _format_ip(pkt[IP].dst, "auto", "integer", "raise")
                    ip_src = cleaned_ip_src[0]
                    ip_dst = cleaned_ip_dst[0]
                    protocol = pkt[IP].proto

                if TCP in pkt:
                    info = pkt[TCP].ack


                # if gl_args.verbose:
                #    print(pkt.frame, time_elapsed, ip_src, ip_dst, protocol, pkt_length, info, target, end='\n')

                if None not in (time_elapsed, ip_src, ip_dst, protocol, info) or self.keep_incomplete:
                    packet_data.append([pkt.frame, time_elapsed, ip_src, ip_dst, protocol, pkt_length, info, target])
                    counter.packet_count_preprocessed += 1

        self.total_packets.value += counter.get_packet_count_total()
        self.in_progress.remove(filename)
        self.completed.append(filename)
        self.display_progress()

        logging.info('File completed: ' + filename)


        # Append data to final CSV file

        self.lock.acquire()
        self.write_data_to_csv(packet_data)
        self.lock.release()

    def start_sniffer(self, file_list):

        if type(file_list) is str:

            self.file_count = 1
            self.run_sniffer(file_list)

        else:

            self.file_count = len(file_list)
            with multiprocessing.Pool(os.cpu_count()) as pool:

                pool.map(self.run_sniffer, file_list)

    def write_data_to_csv(self, data):

        header = True if self.index.value == 0 else False
        mode = 'w' if self.index.value == 0 else 'a'

        new_frame = pd.DataFrame(data, columns=self.columns)
        new_frame.index += self.index.value
        new_frame.to_csv(self.output_file, mode=mode, header=header, index_label='No')
        self.index.value += len(data)

    def display_progress(self):

        print('\x1b[2K\r')
        print('-------------------------------------------------------------------------------------------------')
        print('IN PROGRESS  [' + str(self.file_count - len(self.completed) - len(
            self.in_progress)) + ' files waiting to be processed]' + '\n' + str(
            [i for i in self.in_progress]) + '\n\n' + 'COMPLETED  [' + str(len(self.completed)) + '/' + str(
            self.file_count) + ']' + '\n' + str([i for i in self.completed]))
        print('-------------------------------------------------------------------------------------------------')
        time.sleep(0.25)
