import os
import time
import logging
from ParallelSniffer import Sniffer
import utils
import multiprocessing

if __name__ == '__main__':

    # Capture Program start time and set up multiprocessing manager
    program_start = time.time()
    multiprocessing.freeze_support()
    manager = multiprocessing.Manager()

    # Turn on Logging
    logging.basicConfig(filename='PcapPreprocessor.log', filemode='w', level=logging.DEBUG, format='%(asctime)s %(message)s')

    # Record Starting Time
    startTime = time.time()

    # Parse Command Line Arguments
    gl_args = utils.parse_command_line()

    # Initialize Sniffer Controller Object
    sniffer_controller = Sniffer(manager)
    sniffer_controller.keep_incomplete = gl_args.keep_incomplete

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
                    file_list.append(root + '/' + file)

        # Start ParallelSniffer with list of pcap files
        packet_data = sniffer_controller.start_sniffer(file_list)

    # Update Pandas data frame with processed packet data and output to CSV file
    gl_args.data_frame.df = gl_args.data_frame.df.append(packet_data, ignore_index=True)
    gl_args.data_frame.to_csv()
    program_end = time.time()

    print("Preprocessed " + str(sniffer_controller.total_packets.value) + " packets in " + utils.pretty_time_delta(program_end - program_start))
    print("Program End")
