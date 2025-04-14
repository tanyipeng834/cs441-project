class EthernetFrame:
    def __init__(self, source, destination, data):
        self.source = source
        self.destination = destination
        self.data = data
        self.length = len(data) if data else 0

    def encode(self):
        """Convert Ethernet frame to binary representation"""

        # Create a bytearray for the frame
        result = bytearray()

        # Add source and destination MAC (encoded as UTF-8)
        result.extend(self.source.encode("utf-8"))
        result.extend(self.destination.encode("utf-8"))

        # Prepare data bytes
        data_bytes = bytearray()
        if self.data:
            if isinstance(self.data, str):
                data_bytes = self.data.encode("utf-8")
            elif isinstance(self.data, bytes) or isinstance(self.data, bytearray):
                data_bytes = self.data
            else:
                print(f"[DEBUG] ETHERNET_ENCODE: Unknown data type: {type(self.data)}")

        # Add length byte
        result.append(len(data_bytes) & 0xFF)

        # Add data
        result.extend(data_bytes)

        frame_bytes = bytes(result)

        return frame_bytes

    @staticmethod
    def decode(frame):
        """Decode binary representation back to Ethernet frame"""
        try:
            # Make sure we're working with bytes
            if isinstance(frame, str):
                frame_bytes = bytearray()
                for c in frame:
                    frame_bytes.append(ord(c))
                frame_bytes = bytes(frame_bytes)
            else:
                frame_bytes = frame

            if len(frame_bytes) < 5:
                raise ValueError(
                    f"Frame too short to be an Ethernet frame: length={len(frame_bytes)}"
                )

            # Decode header fields
            source = frame_bytes[0:2].decode("utf-8")
            destination = frame_bytes[2:4].decode("utf-8")
            data_length = frame_bytes[4]

            # Extract data
            data = (
                frame_bytes[5 : 5 + data_length]
                if len(frame_bytes) >= 5 + data_length
                else frame_bytes[5:]
            )

            # Create the Ethernet frame
            eth_frame = EthernetFrame(source, destination, data)

            return eth_frame

        except Exception as e:
            print(f"[ERROR] ETHERNET_DECODE_ERROR: {e}")
            import traceback

            traceback.print_exc()
            raise ValueError(f"Error decoding Ethernet frame: {str(e)}")

    def __str__(self):
        """String representation for debugging"""
        data_len = 0
        if isinstance(self.data, str):
            data_len = len(self.data)
        elif isinstance(self.data, bytes) or isinstance(self.data, bytearray):
            data_len = len(self.data)

        return (
            f"Ethernet[src={self.source}, dst={self.destination}, data_len={data_len}]"
        )
