from scapy.all import *
import torch
from torch_geometric.data import OnDiskDataset, DataLoader
from torch_geometric.transforms import LineGraph
from src.GraphDataset import GraphDataset

def pcap_reader(file):

    for idx, pkt in enumerate(PcapReader(file)):

        print(pkt)
        if idx == 10:
            break


if __name__ == '__main__':

    #file1 = 'Data_Research/attack_1.pcap'

    #pcap_reader(file1)

    db_name = "/home/kgb/PycharmProjects/PcapPreprocessor/NetworkIntrusionDetection"
    dataset = GraphDataset(root=db_name)

    print(dataset)
