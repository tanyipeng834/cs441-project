class IPPacket:
    """
    Represents an IP packet with format:
    Source(1 byte), Destination(1 byte), Protocol(1 byte),
    DataLength(1 byte), Data(up to 256 bytes), Node (optional)
    """

    def __init__(self, source_ip, dest_ip, protocol, data, node=None):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.protocol = protocol
        self.data = data
        self.length = len(data)
        self.node = node  # Node can be None if not passing through router
        
    def encode(self):
        if self.node is None:
            return f"{chr(self.source_ip)}{chr(self.dest_ip)}{chr(self.protocol)}{chr(self.length)}{self.data}"
        else:
            # If node is not None, append the node information
            return f"{chr(self.source_ip)}{chr(self.dest_ip)}{chr(self.protocol)}{chr(self.length)}{self.data}{self.node}"

    @staticmethod
    def decode(packet_data):
        """Decode string representation back to IP packet"""
        try:
            if len(packet_data) < 4:
                raise ValueError("Packet too short to be an IP packet")

            source_ip = ord(packet_data[0])
            dest_ip = ord(packet_data[1])
            protocol = ord(packet_data[2])
            data_length = ord(packet_data[3])

            if len(packet_data) < 4 + data_length:
                raise ValueError(
                    f"Packet truncated: expected {data_length} bytes of data, got {len(packet_data) - 4}"
                )

            data = packet_data[4 : 4 + data_length]

            # Check if there's node data (i.e., if the packet has more data after the data section)
            node = packet_data[4 + data_length:] if len(packet_data) > 4 + data_length else None

            # Return the packet, with node being None if not available
            return IPPacket(source_ip, dest_ip, protocol, data, node)

        except Exception as e:
            raise ValueError(f"Error while decoding packet: {str(e)}")

    def __str__(self):
        """String representation for debugging"""
        return f"IP[src=0x{self.source_ip:02X}, dst=0x{self.dest_ip:02X}, proto={self.protocol}, data='{self.data}', node={self.node}]"
