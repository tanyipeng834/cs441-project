class ARPPacket:
    """
    Represents an ARP packet with format:
    Identifier(3 bytes), Opcode(1 byte), Source MAC(2 bytes), Source IP (1 byte)
    """

    # Gratuitous uses reply opcode
    REPLY = 2

    # Identifier for ARP packets
    IDENTIFIER = b"ARP"

    def __init__(self, opcode, source_mac, source_ip):
        self.opcode = opcode
        self.source_mac = source_mac
        self.source_ip = source_ip

    def encode(self):
        """Convert ARP packet to binary representation"""
        result = bytearray()

        # Add identifier
        result.extend(ARPPacket.IDENTIFIER)

        # Add opcode
        result.append(self.opcode & 0xFF)

        # Add source MAC (convert to bytes if it's a string)
        if isinstance(self.source_mac, str):
            result.extend(self.source_mac.encode("utf-8"))
        else:
            result.extend(self.source_mac)

        # Add source IP
        result.append(self.source_ip & 0xFF)

        return bytes(result)

    @staticmethod
    def decode(packet_data):
        """Decode binary representation back to ARP packet"""
        try:
            # Convert to bytes if needed
            if isinstance(packet_data, str):
                packet_bytes = packet_data.encode("utf-8")
            else:
                packet_bytes = packet_data

            # Check for minimum length
            if len(packet_bytes) < 7:  # ARP(3) + opcode(1) + mac(2) + ip(1)
                raise ValueError(f"Packet too short: length={len(packet_bytes)}")

            # Check for ARP identifier
            if not packet_bytes.startswith(ARPPacket.IDENTIFIER):
                raise ValueError("Packet doesn't start with ARP identifier")

            # Extract fields
            opcode = packet_bytes[3]
            source_mac = packet_bytes[4:6].decode("utf-8")
            source_ip = packet_bytes[6]

            return ARPPacket(opcode, source_mac, source_ip)
        except Exception as e:
            raise ValueError(f"Failed to decode ARP packet: {e}")

    def __str__(self):
        """String representation for debugging"""
        return f"ARP[opcode={self.opcode}, src_mac={self.source_mac}, src_ip=0x{self.source_ip:02X}]"
