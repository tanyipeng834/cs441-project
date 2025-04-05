import traceback


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
        """Convert TCP packet to binary representation"""
        # print(f"[DEBUG] TCP_ENCODE: START - packet={self}")
        # print(
        #     f"[DEBUG] TCP_ENCODE: src_port={self.src_port}, dst_port={self.dest_port}, seq={self.seq_num}, ack={self.ack_num}, flags={self.flags}"
        # )

        # Create a bytearray for the packet
        result = bytearray()

        # Add source and destination ports (1 byte each)
        result.append(self.src_port & 0xFF)
        result.append(self.dest_port & 0xFF)

        # Add sequence number (2 bytes, big endian)
        result.append((self.seq_num >> 8) & 0xFF)
        result.append(self.seq_num & 0xFF)

        # Add acknowledgment number (2 bytes, big endian)
        result.append((self.ack_num >> 8) & 0xFF)
        result.append(self.ack_num & 0xFF)

        # Add flags (1 byte)
        result.append(self.flags & 0xFF)

        # Add data if any
        if self.data:
            if isinstance(self.data, str):
                result.extend(self.data.encode("utf-8"))
            elif isinstance(self.data, bytes) or isinstance(self.data, bytearray):
                result.extend(self.data)
            # else:
            #     print(f"[DEBUG] TCP_ENCODE: Unknown data type: {type(self.data)}")

        # Convert to bytes object
        packet_bytes = bytes(result)

        # print(
        #     f"[DEBUG] TCP_ENCODE: header_length=7, data_length={len(packet_bytes) - 7}"
        # )
        # print(
        #     f"[DEBUG] TCP_ENCODE: header bytes in hex: {' '.join([f'{b:02X}' for b in packet_bytes[:7]])}"
        # )
        # print(
        #     f"[DEBUG] TCP_ENCODE: result_type={type(packet_bytes)}, length={len(packet_bytes)}"
        # )
        # print(
        #     f"[DEBUG] TCP_ENCODE: first 10 bytes: {' '.join([f'{b:02X}' for b in packet_bytes[:10]])}"
        # )
        # print(f"[DEBUG] TCP_ENCODE: END")

        return packet_bytes

    @staticmethod
    def decode(packet_data):
        """Decode binary representation back to TCP packet"""
        try:
            # print(f"[DEBUG] TCP_DECODE: START")
            # print(
            #     f"[DEBUG] TCP_DECODE: data_type={type(packet_data)}, length={len(packet_data)}"
            # )

            # Make sure we're working with bytes
            if isinstance(packet_data, str):
                # print(f"[DEBUG] TCP_DECODE: Converting string to bytes")
                packet_bytes = bytearray()
                for c in packet_data:
                    packet_bytes.append(ord(c))
                packet_bytes = bytes(packet_bytes)
            else:
                packet_bytes = packet_data

            # print(
            #     f"[DEBUG] TCP_DECODE: packet_bytes: {' '.join([f'{b:02X}' for b in packet_bytes[:min(10, len(packet_bytes))]])}"
            # )

            if len(packet_bytes) < 7:
                raise ValueError(
                    f"Packet too short to be a TCP packet: length={len(packet_bytes)}"
                )

            # Extract header fields
            src_port = packet_bytes[0]
            dest_port = packet_bytes[1]
            seq_num = (packet_bytes[2] << 8) + packet_bytes[3]
            ack_num = (packet_bytes[4] << 8) + packet_bytes[5]
            flags = packet_bytes[6]

            # print(
            #     f"[DEBUG] TCP_DECODE: src_port={src_port}, dst_port={dest_port}, seq={seq_num}, ack={ack_num}, flags={flags}"
            # )

            # Extract data (remaining bytes after header)
            data = b""
            if len(packet_bytes) > 7:
                data = packet_bytes[7:]
                # print(
                #     f"[DEBUG] TCP_DECODE: data length={len(data)}, first few bytes: {' '.join([f'{b:02X}' for b in data[:min(10, len(data))]])}"
                # )
            # else:
            #     print(f"[DEBUG] TCP_DECODE: no data present")

            # Create the TCP packet
            packet = TCPPacket(src_port, dest_port, seq_num, ack_num, flags, data)
            # print(f"[DEBUG] TCP_DECODE: Created packet: {packet}")
            # print(f"[DEBUG] TCP_DECODE: END")

            return packet
        except Exception as e:
            print(f"[ERROR] TCP_DECODE_ERROR: {e}")
            traceback.print_exc()
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

        data_len = 0
        if isinstance(self.data, str):
            data_len = len(self.data)
        elif isinstance(self.data, bytes) or isinstance(self.data, bytearray):
            data_len = len(self.data)

        return (
            f"TCP[src_port={self.src_port}, dst_port={self.dest_port}, "
            f"seq={self.seq_num}, ack={self.ack_num}, flags={flags}, "
            f"data_len={data_len}]"
        )
