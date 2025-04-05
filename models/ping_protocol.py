class PingProtocol:
    """
    Represents the PingProtocol with format:
    Type(1 byte), Code(1 byte), Identifier(1 byte), Sequence(1 byte), Data(variable)
    """

    PROTOCOL = 0

    # Type constants
    ECHO_REPLY = 0
    DEST_UNREACHABLE = 3
    ECHO_REQUEST = 8
    TIME_EXCEEDED = 11

    # Code constants
    NET_UNREACHABLE = 0
    HOST_UNREACHABLE = 1
    PROTOCOL_UNREACHABLE = 2
    PORT_UNREACHABLE = 3

    def __init__(self, ping_type, code=0, identifier=0, sequence=0, data=""):
        self.ping_type = ping_type
        self.code = code
        self.identifier = identifier
        self.sequence = sequence
        self.data = data

    def encode(self):
        """Convert PingProtocol to binary representation"""
        # Create a bytearray for the packet
        result = bytearray()

        # Add header fields (each 1 byte)
        result.append(self.ping_type & 0xFF)
        result.append(self.code & 0xFF)
        result.append(self.identifier & 0xFF)
        result.append(self.sequence & 0xFF)

        # Add data if any
        if self.data:
            if isinstance(self.data, str):
                result.extend(self.data.encode("utf-8"))
            elif isinstance(self.data, bytes) or isinstance(self.data, bytearray):
                result.extend(self.data)

        return bytes(result)

    @staticmethod
    def decode(packet_data):
        """Decode binary representation back to PingProtocol packet"""
        try:
            # Make sure we're working with bytes
            if isinstance(packet_data, str):
                # Convert string to bytes
                packet_bytes = bytearray()
                for c in packet_data:
                    packet_bytes.append(ord(c))
                packet_bytes = bytes(packet_bytes)
            else:
                packet_bytes = packet_data

            if len(packet_bytes) < 4:
                raise ValueError(
                    "PingProtocol packet too short, minimum length is 4 bytes"
                )

            # Extract header fields
            ping_type = packet_bytes[0]
            code = packet_bytes[1]
            identifier = packet_bytes[2]
            sequence = packet_bytes[3]

            # Extract data (remaining bytes after header)
            data = b""
            if len(packet_bytes) > 4:
                data = packet_bytes[4:]

                # Try to convert to string if it's a valid UTF-8 sequence
                try:
                    data = data.decode("utf-8")
                except UnicodeDecodeError:
                    # Keep as bytes if not a valid UTF-8 sequence
                    pass

            # Create the PingProtocol packet
            packet = PingProtocol(ping_type, code, identifier, sequence, data)
            return packet

        except Exception as e:
            import traceback

            traceback.print_exc()
            raise ValueError(f"Failed to decode PingProtocol packet: {e}")

    @staticmethod
    def create_echo_request(identifier, sequence, data=""):
        """Factory method to create an Echo Request (ping)"""
        return PingProtocol(PingProtocol.ECHO_REQUEST, 0, identifier, sequence, data)

    @staticmethod
    def create_echo_reply(identifier, sequence, data=""):
        """Factory method to create an Echo Reply (pong)"""
        return PingProtocol(PingProtocol.ECHO_REPLY, 0, identifier, sequence, data)

    def is_echo_request(self):
        """Check if this packet is an echo request"""
        return self.ping_type == PingProtocol.ECHO_REQUEST

    def is_echo_reply(self):
        """Check if this packet is an echo reply"""
        return self.ping_type == PingProtocol.ECHO_REPLY

    def __str__(self):
        """String representation for debugging"""
        type_names = {
            0: "ECHO_REPLY",
            3: "DEST_UNREACHABLE",
            8: "ECHO_REQUEST",
            11: "TIME_EXCEEDED",
        }
        type_name = type_names.get(self.ping_type, str(self.ping_type))

        data_len = 0
        if isinstance(self.data, str):
            data_len = len(self.data)
        elif isinstance(self.data, bytes) or isinstance(self.data, bytearray):
            data_len = len(self.data)

        data_repr = (
            f"'{self.data}'"
            if isinstance(self.data, str)
            else f"<binary data of {data_len} bytes>"
        )

        return f"PingProtocol[type={type_name}, code={self.code}, id={self.identifier}, seq={self.sequence}, data={data_repr}]"
