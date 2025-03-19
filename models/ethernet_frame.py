class EthernetFrame:
    def __init__(self, source, destination, data):
        self.source = source
        self.destination = destination
        self.data = data
        self.length = len(data)

    def encode(self):

        if not isinstance(self.data,bytes):
            self.data = self.data.encode("utf-8")
        
        
        
        frame = f"{self.source}{self.destination}{chr(len(self.data))}"
        frame =  frame.encode("utf-8") + self.data
        return frame
  