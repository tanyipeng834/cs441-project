import sys
import atexit
from models.arp_poisoning_node import ARPPoisoningNode
from utils.routing import R2_ARP_TABLE, R2_NETWORK


if __name__ == "__main__":
    # Create Node 1 with IP address 0x1A
    node = ARPPoisoningNode("N2", 0x2A, 50002, R2_NETWORK, default_gateway="R2")

    # Initialize ARP table - Node2 knows about itself, Node3, and R2 in its network
    node.init_arp_table(
        # Self  # Node3  # Router interface R2
        R2_ARP_TABLE
    )

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
