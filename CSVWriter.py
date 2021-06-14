import csv
import logging
import sys

log = logging.getLogger('main.main')


class _CSVWriter:

    def __init__(self, fileName):
        try:
            # creater a writer object and write the header row
            self.csvFile = open(fileName, 'w', newline='')
            self.writer = csv.writer(self.csvFile, delimiter=',')
            self.writer.writerow(('No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'Target'))
            self.rows = []
        except:
            error = str(sys.exc_info()[0:2])
            log.error('CVS File Failure: ' + error)

    def writeCSVRow(self, frame, time, source_ip, dest_ip, protocol, length, info, target):

        if frame % 500 == 0:

            self.writer.writerows(self.rows)
            self.rows.clear()

        else:

            self.rows.append([str(frame), str(time), source_ip, dest_ip, str(protocol), str(length), str(info), str(target)])

    def writerClose(self):
        self.writer.writerows(self.rows)
        self.csvFile.close()
