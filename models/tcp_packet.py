class TCPPacket:
    """
    Represents a simplified TCP packet with format:
    Source Port(1 byte), Destination Port(1 byte), Sequence Number(2 bytes),
    Acknowledgment Number(2 bytes), Flags(1 byte), Data(variable)

    Flags byte:
    - SYN (0x02) - Start connection
    - ACK (0x10) - Acknowledge
    - FIN (0x01) - End connection
    - RST (0x04) - Reset connection
    - PSH (0x08) - Push data
    """

    # Flag constants
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10

    # Protocol number (for IP packets)
    PROTOCOL = 6  # TCP protocol number

    def __init__(self, src_port, dest_port, seq_num, ack_num, flags, data=""):
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.data = data

    def encode(self):
        """Convert TCP packet to string representation"""
        # Encode the sequence and acknowledgment numbers (2 bytes each)
        seq_bytes = chr(self.seq_num >> 8) + chr(self.seq_num & 0xFF)
        ack_bytes = chr(self.ack_num >> 8) + chr(self.ack_num & 0xFF)

        # Combine all fields
        header = f"{chr(self.src_port)}{chr(self.dest_port)}{seq_bytes}{ack_bytes}{chr(self.flags)}"
        return header + self.data

    @staticmethod
    def decode(packet_data):
        """Decode string representation back to TCP packet"""
        try:
            if len(packet_data) < 7:
                raise ValueError("Packet too short to be a TCP packet")

            src_port = ord(packet_data[0])
            dest_port = ord(packet_data[1])

            # Decode sequence and acknowledgment numbers (2 bytes each)
            seq_num = (ord(packet_data[2]) << 8) + ord(packet_data[3])
            ack_num = (ord(packet_data[4]) << 8) + ord(packet_data[5])

            flags = ord(packet_data[6])

            # Extract data
            data = packet_data[7:] if len(packet_data) > 7 else ""

            return TCPPacket(src_port, dest_port, seq_num, ack_num, flags, data)
        except Exception as e:
            raise ValueError(f"Failed to decode TCP packet: {e}")

    def is_syn(self):
        """Check if this is a SYN packet"""
        return (self.flags & TCPPacket.SYN) != 0

    def is_ack(self):
        """Check if this is an ACK packet"""
        return (self.flags & TCPPacket.ACK) != 0

    def is_fin(self):
        """Check if this is a FIN packet"""
        return (self.flags & TCPPacket.FIN) != 0

    def is_rst(self):
        """Check if this is a RST packet"""
        return (self.flags & TCPPacket.RST) != 0

    def is_psh(self):
        """Check if this is a PSH packet"""
        return (self.flags & TCPPacket.PSH) != 0

    def __str__(self):
        """String representation for debugging"""
        flag_str = []
        if self.is_fin():
            flag_str.append("FIN")
        if self.is_syn():
            flag_str.append("SYN")
        if self.is_rst():
            flag_str.append("RST")
        if self.is_psh():
            flag_str.append("PSH")
        if self.is_ack():
            flag_str.append("ACK")

        flags = "|".join(flag_str) if flag_str else "NONE"

        return (
            f"TCP[src_port={self.src_port}, dst_port={self.dest_port}, "
            f"seq={self.seq_num}, ack={self.ack_num}, flags={flags}, "
            f"data_len={len(self.data)}]"
        )
