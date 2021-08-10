import pandas as pd


class PacketData:

    def __init__(self, fileName):
        self.df = pd.DataFrame(columns=['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'Target'])
        self.csv_name = fileName

    def to_csv(self):
        self.df.to_csv(self.csv_name, index=False)



