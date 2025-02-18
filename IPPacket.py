class IPPacket:
    """Represents an IP packet with the required fields"""
    
    def __init__(self, source, destination, protocol, data):
        """
        Initialize an IP packet
        source: 1 byte (e.g., 0x1A for Node1)
        destination: 1 byte (e.g., 0x2A for Node2)
        protocol: 1 byte (0 for ping)
        data: string data that will be encoded to bytes
        """
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.data = data
        self.length = len(data.encode('utf-8'))  # Get length of encoded data

    def encode(self):
        """
        Encode the IP packet into a format suitable for the Ethernet frame's data field
        Format: Source(1) + Destination(1) + Protocol(1) + DataLength(1) + Data
        Returns: bytes
        """
        # Convert the header fields to bytes
        header = bytes([
            self.source,
            self.destination,
            self.protocol,
            self.length
        ])
        # Combine header with data
        return header + self.data.encode('utf-8')

    @staticmethod
    def decode(raw_data):
        """
        Decode raw bytes back into an IP packet
        """
        if isinstance(raw_data, str):
            raw_data = raw_data.encode('utf-8')

        # Extract header fields
        source = raw_data[0]
        destination = raw_data[1]
        protocol = raw_data[2]
        length = raw_data[3]
        
        # Extract and decode data
        data = raw_data[4:4 + length].decode('utf-8')
        
        return IPPacket(source, destination, protocol, data)

# IP address mapping for convenience
IP_ADDRESSES = {
    'N1': 0x1A,
    'N2': 0x2A,
    'N3': 0x2B,
    'R1': 0x11,
    'R2': 0x21
}