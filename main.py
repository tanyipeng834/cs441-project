from node import Node
from network import Network


class NetworkEmulator:
    def __init__(self):
        """
        Initialize the networks and nodes, and add the nodes to the corresponding networks.
        """
        # Create two LAN networks
        self.lan_1 = Network()
        self.lan_2 = Network()

        self.node1 = Node("N1", 50001, self.lan_1)
        self.node2 = Node("N2", 50002, self.lan_2)
        self.node3 = Node("N3", 50003, self.lan_2)
        self.router_interface_1 = Node("R1", 50004, self.lan_1)
        self.router_interface_2 = Node("R2", 50005, self.lan_2)

        self.lan_1.add_node(self.node1)
        self.lan_1.add_node(self.router_interface_1)

        self.lan_2.add_node(self.node2)
        self.lan_2.add_node(self.router_interface_2)
        self.lan_2.add_node(self.node3)

    def run(self):
        self.node2.send_frame("N3", "Hello World, Coming from N2")

    def shutdown(self):
        self.node1.shutdown()
        self.node2.shutdown()
        self.node3.shutdown()
        self.router_interface_1.shutdown()
        self.router_interface_2.shutdown()


if __name__ == "__main__":
    emulator = NetworkEmulator()

    emulator.run()

    emulator.shutdown()
