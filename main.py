import os
import time
import logging
from src.Sniffer import Sniffer
#from src.CsvWriter import CsvWriter

from src import utils
from scapy.all import rdpcap

logging.raiseExceptions = True

if __name__ == '__main__':

    # Capture Program start time and set up multiprocessing manager
    program_start = time.time()

    # Turn on Logging
    logging.basicConfig(filename='PcapPreprocessor.log', filemode='w', level=logging.DEBUG, format='%(asctime)s %(message)s')

    # Record Starting Time
    startTime = time.time()

    # Parse Command Line Arguments
    gl_args = utils.parse_command_line()


    # Initialize Sniffer Controller Object
    sniffer_controller = Sniffer(gl_args.output_file)

    packet_data = []

    if gl_args.input_file:

        # Start ParallelSniffer with single pcap file
        packet_data = sniffer_controller.run_sniffer(gl_args.input_file)

    elif gl_args.input_directory:

        logging.info('Directory Parsing Started at: ' + gl_args.input_directory + '/')
        print('Directory Parsing Started at: ' + gl_args.input_directory + '/')

        # Create a loop that finds all pcap files starting at rootPath, all subdirectories will also be processed

        file_list = []
        for root, dirs, files in os.walk(gl_args.input_directory):
            for file in files:
                if file.endswith('.pcap' or '.pcapng'):
                    file_path = root + '/' + file
                    file_list.append(file_path)

        # Start ParallelSniffer with list of pcap files

        results = sniffer_controller.start_sniffer(file_list[-1], parallel=False)

    program_end = time.time()
    sniffer_controller.print_end_message(program_end - program_start)
