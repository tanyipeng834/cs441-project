class PingProtocol:
    """
    Represents the PingProtocol with format:
    Type(1 byte), Code(1 byte), Identifier(1 byte), Sequence(1 byte), Data(variable)

    """

    PROTOCOL = 1

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
        """Convert PingProtocol to string representation"""
        header = f"{chr(self.ping_type)}{chr(self.code)}{chr(self.identifier)}{chr(self.sequence)}"
        return header + self.data

    @staticmethod
    def decode(packet_data):
        """Decode string representation back to PingProtocol packet"""
        if len(packet_data) < 4:
            raise ValueError("PingProtocol too short")

        ping_type = ord(packet_data[0])
        code = ord(packet_data[1])
        identifier = ord(packet_data[2])
        sequence = ord(packet_data[3])
        data = packet_data[4:] if len(packet_data) > 4 else ""

        return PingProtocol(ping_type, code, identifier, sequence, data)

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
        return f"PingProtocol[type={type_name}, code={self.code}, id={self.identifier}, seq={self.sequence}, data='{self.data}']"
