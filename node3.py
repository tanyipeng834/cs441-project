import sys
import atexit
from models.sniffing_node import SniffingNode
from models.firewall_node import FirewallNode
from utils.routing import R2_ARP_TABLE,R2_NETWORK


class Node3(SniffingNode, FirewallNode):
    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)


if __name__ == "__main__":
    # Create Node 3 with IP address 0x2B as both a sniffing and firewall node
    node = Node3("N3", 0x2B, 50003, R2_NETWORK, default_gateway="R2")

    # Initialize ARP table - Node3 knows about itself, Node2, and R2 in its network
    node.init_arp_table(
        R2_ARP_TABLE  # Self  # Node2  # Router interface R2
    )

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
