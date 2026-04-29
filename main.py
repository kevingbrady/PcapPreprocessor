import os
import time
import logging
import warnings
from src.Sniffer import Sniffer

from src import utils

logging.raiseExceptions = True
warnings.filterwarnings("ignore", category=UserWarning)


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
    sniffer_controller = Sniffer(gl_args.output_database_name)
    file_list = []

    if gl_args.input_file:

        # Append file to file list if it is just one capture file
        file_list.append(gl_args.input_file)

    elif gl_args.input_directory:

        logging.info('Directory Parsing Started at: ' + gl_args.input_directory + '/')
        #print('Directory Parsing Started at: ' + gl_args.input_directory + '/')
        #print("\n\n")

        # Create a loop that finds all pcap files starting at rootPath, all subdirectories will also be processed

        for root, dirs, files in os.walk(gl_args.input_directory):
            for file in files:
                if file.endswith('.pcap' or '.pcapng'):
                    file_path = root + '/' + file
                    file_list.append(file_path)

        # Sort files by size with the largest files at the front of the list
        file_list = sorted(file_list, key=lambda file: os.path.getsize(file), reverse=True)

    # Start ParallelSniffer with list of pcap files
    sniffer_controller.start_sniffer(file_list, write_to_db=False, display_progress=False, parallel=False)
    program_end = time.time()
    sniffer_controller.print_end_message(program_end - program_start)
