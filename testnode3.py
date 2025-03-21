import sys
import atexit
from models.tcp_hijacking_node import TCPHijackingNode
from models.firewall_node import FirewallNode


class Node3(TCPHijackingNode, FirewallNode):
    """
    Node3 with combined capabilities:
    - TCP Hijacking for MITM attacks
    - Firewall functionality
    - Sniffing capability (inherited from TCPHijackingNode)
    """

    def __init__(self, mac_address, ip_address, port, network, default_gateway=None):
        super().__init__(mac_address, ip_address, port, network, default_gateway)


if __name__ == "__main__":
    # Create Node 3 with IP address 0x2B as a hijacking, sniffing, and firewall node
    node = Node3("N3", 0x2B, 50003, ["N2", "N3", "R2"], default_gateway="R2")

    # Initialize ARP table - Node3 knows about itself, Node2, and R2 in its network
    node.init_arp_table(
        {0x2B: "N3", 0x2A: "N2", 0x21: "R2"}  # Self  # Node2  # Router interface R2
    )

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
