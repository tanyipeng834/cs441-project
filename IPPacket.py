class IPPacket:
    PROTOCOL_PING = 0x01

    def __init__(self, source, destination, protocol, data):
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.data = data
        self.length = len(data)

    def encode(self):
        """
        Encode the IP packet into a string format
        Format: Source(1) + Destination(1) + Protocol(1) + DataLength(1) + Data
        """
        packet = (
            chr(self.source) +
            chr(self.destination) +
            chr(self.protocol) +
            chr(self.length) +
            self.data
        )
        return packet

    @staticmethod
    def decode(packet_str):
        """
        Decode a packet string back into an IPPacket object
        """
        if len(packet_str) < 4:
            return None
            
        source = ord(packet_str[0])
        destination = ord(packet_str[1])
        protocol = ord(packet_str[2])
        data_length = ord(packet_str[3])
        data = packet_str[4:4 + data_length]
        
        return IPPacket(source, destination, protocol, data)