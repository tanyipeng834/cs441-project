class EthernetFrame:
    def __init__(self, source, destination, data):
        self.source = source
        self.destination = destination
        self.data = data
        self.length = len(data) if data else 0

    def encode(self):
        """Convert Ethernet frame to binary representation"""
        # print(
        #     f"[DEBUG] ETHERNET_ENCODE: START - source={self.source}, destination={self.destination}, data_length={self.length}"
        # )
        # print(f"[DEBUG] ETHERNET_ENCODE: data_type={type(self.data)}")

        # Create a bytearray for the frame
        result = bytearray()

        # Add source and destination MAC (encoded as UTF-8)
        result.extend(self.source.encode("utf-8"))
        result.extend(self.destination.encode("utf-8"))

        # Prepare data bytes
        data_bytes = bytearray()
        if self.data:
            if isinstance(self.data, str):
                # print(f"[DEBUG] ETHERNET_ENCODE: data is string, converting to bytes")
                data_bytes = self.data.encode("utf-8")
            elif isinstance(self.data, bytes) or isinstance(self.data, bytearray):
                # print(f"[DEBUG] ETHERNET_ENCODE: data is already bytes")
                data_bytes = self.data
            # else:
            #     print(f"[DEBUG] ETHERNET_ENCODE: Unknown data type: {type(self.data)}")

        # Add length byte
        result.append(len(data_bytes) & 0xFF)
        # print(f"[DEBUG] ETHERNET_ENCODE: data length byte: {len(data_bytes):02X}")

        # Add data
        result.extend(data_bytes)

        frame_bytes = bytes(result)

        # print(
        #     f"[DEBUG] ETHERNET_ENCODE: header_length=5, data_length={len(data_bytes)}"
        # )
        # print(
        #     f"[DEBUG] ETHERNET_ENCODE: header bytes: {' '.join([f'{b:02X}' for b in frame_bytes[:5]])}"
        # )
        # if len(data_bytes) > 0:
        #     print(
        #         f"[DEBUG] ETHERNET_ENCODE: first few data bytes: {' '.join([f'{b:02X}' for b in data_bytes[:min(10, len(data_bytes))]])}"
        #     )
        # print(
        #     f"[DEBUG] ETHERNET_ENCODE: final frame_type={type(frame_bytes)}, frame_length={len(frame_bytes)}"
        # )
        # print(f"[DEBUG] ETHERNET_ENCODE: END")

        return frame_bytes

    @staticmethod
    def decode(frame):
        """Decode binary representation back to Ethernet frame"""
        try:
            # print(
            #     f"[DEBUG] ETHERNET_DECODE: START - frame_type={type(frame)}, frame_length={len(frame)}"
            # )

            # Make sure we're working with bytes
            if isinstance(frame, str):
                # print(f"[DEBUG] ETHERNET_DECODE: Converting string to bytes")
                frame_bytes = bytearray()
                for c in frame:
                    frame_bytes.append(ord(c))
                frame_bytes = bytes(frame_bytes)
            else:
                frame_bytes = frame

            # print(
            #     f"[DEBUG] ETHERNET_DECODE: frame_bytes: {' '.join([f'{b:02X}' for b in frame_bytes[:min(15, len(frame_bytes))]])}"
            # )

            if len(frame_bytes) < 5:
                raise ValueError(
                    f"Frame too short to be an Ethernet frame: length={len(frame_bytes)}"
                )

            # Decode header fields
            source = frame_bytes[0:2].decode("utf-8")
            destination = frame_bytes[2:4].decode("utf-8")
            data_length = frame_bytes[4]

            # print(
            #     f"[DEBUG] ETHERNET_DECODE: source={source}, destination={destination}, data_length={data_length}"
            # )

            # if len(frame_bytes) < 5 + data_length:
            #     print(
            #         f"[DEBUG] ETHERNET_DECODE: Frame truncated: expected {5 + data_length} bytes, got {len(frame_bytes)}"
            #     )

            # Extract data
            data = (
                frame_bytes[5 : 5 + data_length]
                if len(frame_bytes) >= 5 + data_length
                else frame_bytes[5:]
            )
            # print(
            #     f"[DEBUG] ETHERNET_DECODE: data length={len(data)}, first few bytes: {' '.join([f'{b:02X}' for b in data[:min(10, len(data))]])}"
            # )

            # Create the Ethernet frame
            eth_frame = EthernetFrame(source, destination, data)
            # print(f"[DEBUG] ETHERNET_DECODE: END")

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
