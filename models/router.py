import socket

from .ethernet_frame import EthernetFrame
from .node import Node


class Router(Node):
    def __init__(self, mac_address, port, router_interfaces):
        super().__init__(
            mac_address, port, []
        )  # Empty network as router handles routing differently
        self.router_interfaces = router_interfaces

    def send_frame(self, destination, data, interface):
        """
        Override send_frame to handle router-specific sending logic
        """
        for node in self.router_interfaces[interface]:
            destination_port = self.process_node_mac(node)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((Node.HOST_IP, destination_port))
                    frame = EthernetFrame(self.mac_address, destination, data)
                    s.sendall(frame.encode())
            except Exception as e:
                print(
                    f"Error sending frame from {self.mac_address} to {destination_port}: {e}"
                )

    def process_frame(self, frame):
        """
        Override process_frame to handle router-specific frame processing
        """
        if len(frame) < 5:
            print(f"Node {self.mac_address} received invalid frame: {frame}")
            return

        source = frame[0:2]
        destination = frame[2:4]
        data_length = ord(frame[4:5])
        data = frame[5 : 5 + data_length]

        if destination in self.router_interfaces:
            print(
                f"Router received data on interface {destination} from {source}: {data}"
            )
        else:
            print(f"Router dropped frame from {source} intended for {destination}")
