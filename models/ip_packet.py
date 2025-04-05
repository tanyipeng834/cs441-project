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
        self.length = len(data) if data else 0
        self.node = node  # Node can be None if not passing through router

    def encode(self):
        """Convert IP packet to binary representation"""
        # print(f"[DEBUG] IP_ENCODE: START - packet={self}")
        # print(
        #     f"[DEBUG] IP_ENCODE: source_ip=0x{self.source_ip:02X}, dest_ip=0x{self.dest_ip:02X}, protocol={self.protocol}"
        # )

        # Create a bytearray for the packet
        result = bytearray()

        # Add header fields (each 1 byte)
        result.append(self.source_ip & 0xFF)
        result.append(self.dest_ip & 0xFF)
        result.append(self.protocol & 0xFF)

        # Prepare data
        data_bytes = bytearray()
        if self.data:
            if isinstance(self.data, str):
                data_bytes = self.data.encode("utf-8")
            elif isinstance(self.data, bytes) or isinstance(self.data, bytearray):
                data_bytes = self.data
            # else:
            #     print(f"[DEBUG] IP_ENCODE: Unknown data type: {type(self.data)}")

        # Add data length
        result.append(len(data_bytes) & 0xFF)
        # print(f"[DEBUG] IP_ENCODE: data length byte: {len(data_bytes):02X}")

        # Add header bytes in hex for debugging
        header_hex = " ".join([f"{b:02X}" for b in result])
        # print(f"[DEBUG] IP_ENCODE: header bytes in hex: {header_hex}")

        # Add data
        result.extend(data_bytes)

        # Add node information if present
        if self.node is not None:
            if isinstance(self.node, str):
                result.extend(self.node.encode("utf-8"))
            elif isinstance(self.node, bytes) or isinstance(self.node, bytearray):
                result.extend(self.node)
            # else:
            #     print(f"[DEBUG] IP_ENCODE: Unknown node type: {type(self.node)}")

        packet_bytes = bytes(result)

        # print(
        #     f"[DEBUG] IP_ENCODE: data_type={type(data_bytes)}, data_len={len(data_bytes)}"
        # )
        # if len(data_bytes) > 0:
        #     print(
        #         f"[DEBUG] IP_ENCODE: first few data bytes: {' '.join([f'{b:02X}' for b in data_bytes[:min(10, len(data_bytes))]])}"
        #     )

        # print(
        #     f"[DEBUG] IP_ENCODE: final packet_type={type(packet_bytes)}, packet_length={len(packet_bytes)}"
        # )
        # print(
        #     f"[DEBUG] IP_ENCODE: first few packet bytes: {' '.join([f'{b:02X}' for b in packet_bytes[:min(15, len(packet_bytes))]])}"
        # )
        # print(f"[DEBUG] IP_ENCODE: END")

        return packet_bytes

    @staticmethod
    def decode(packet_data):
        """Decode binary representation back to IP packet"""
        try:
            # print(f"[DEBUG] IP_DECODE: START")
            # print(
            #     f"[DEBUG] IP_DECODE: data_type={type(packet_data)}, length={len(packet_data)}"
            # )

            # Make sure we're working with bytes
            if isinstance(packet_data, str):
                # print(f"[DEBUG] IP_DECODE: Converting string to bytes")
                packet_bytes = bytearray()
                for c in packet_data:
                    packet_bytes.append(ord(c))
                packet_bytes = bytes(packet_bytes)
            else:
                packet_bytes = packet_data

            # print(
            #     f"[DEBUG] IP_DECODE: packet_bytes: {' '.join([f'{b:02X}' for b in packet_bytes[:min(15, len(packet_bytes))]])}"
            # )

            if len(packet_bytes) < 4:
                raise ValueError(
                    f"Packet too short to be an IP packet: length={len(packet_bytes)}"
                )

            # Extract header fields
            source_ip = packet_bytes[0]
            dest_ip = packet_bytes[1]
            protocol = packet_bytes[2]
            data_length = packet_bytes[3]

            # print(
            #     f"[DEBUG] IP_DECODE: header values - source_ip=0x{source_ip:02X}, dest_ip=0x{dest_ip:02X}, protocol={protocol}, data_length={data_length}"
            # )

            if len(packet_bytes) < 4 + data_length:
                raise ValueError(
                    f"Packet truncated: expected {data_length} bytes of data, got {len(packet_bytes) - 4}"
                )

            # Extract data
            data = packet_bytes[4 : 4 + data_length]
            # print(
            #     f"[DEBUG] IP_DECODE: data length={len(data)}, first few bytes: {' '.join([f'{b:02X}' for b in data[:min(10, len(data))]])}"
            # )

            # Check for node data
            node = None
            if len(packet_bytes) > 4 + data_length:
                node = packet_bytes[4 + data_length :]
                # print(f"[DEBUG] IP_DECODE: node data present, length={len(node)}")

            # Create the IP packet
            packet = IPPacket(source_ip, dest_ip, protocol, data, node)
            # print(f"[DEBUG] IP_DECODE: Created packet: {packet}")
            # print(f"[DEBUG] IP_DECODE: END")

            return packet

        except Exception as e:
            print(f"[ERROR] IP_DECODE_ERROR: {e}")
            import traceback

            traceback.print_exc()
            raise ValueError(f"Error while decoding packet: {str(e)}")

    def __str__(self):
        """String representation for debugging"""
        data_len = 0
        if isinstance(self.data, str):
            data_len = len(self.data)
        elif isinstance(self.data, bytes) or isinstance(self.data, bytearray):
            data_len = len(self.data)

        return f"IP[src=0x{self.source_ip:02X}, dst=0x{self.dest_ip:02X}, proto={self.protocol}, data_len={data_len}, node={self.node}]"
