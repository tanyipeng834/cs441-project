class EthernetFrame:
    def __init__(self, source, destination, data):
        self.source = source
        self.destination = destination
        self.data = data
        self.length = len(data)

    def encode(self):
        frame = f"{self.source}{self.destination}{chr(len(self.data))}{self.data}"
        return frame.encode('utf-8')