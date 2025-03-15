class ARPPacket:
    """
    Represents an ARP packet with format:
    Opcode(1 byte), Source MAC(2 bytes), Source IP (1 byte)
    """

    # Gratuitous uses reply opcode
    REPLY = 2

    def __init__(self, opcode, source_mac, source_ip):
        self.opcode = opcode
        self.source_mac = source_mac
        self.source_ip = source_ip

    def encode(self):
        """Convert ARP packet to string representation"""
        # Add 'ARP' prefix to identify ARP packets
        return f"ARP{chr(self.opcode)}{self.source_mac}{chr(self.source_ip)}"

    @staticmethod
    def decode(packet_data):
        """Decode string representation back to ARP packet"""
        try:
            if len(packet_data) != 7:  # 'ARP' (3) + opcode (1) + mac (2) + ip (1)
                raise ValueError("Packet must be exactly 7 bytes long to be an ARP packet")
            if not packet_data.startswith("ARP"):
                raise ValueError("Packet must start with 'ARP' to be an ARP packet")

            opcode = ord(packet_data[3])
            source_mac = packet_data[4:6]
            source_ip = ord(packet_data[6])

            return ARPPacket(opcode, source_mac, source_ip)
        except Exception as e:
            raise ValueError(f"Failed to decode ARP packet: {e}")

    def __str__(self):
        """String representation for debugging"""
        return f"ARP[opcode={self.opcode}, src_mac={self.source_mac}, src_ip=0x{self.source_ip:02X}]"
