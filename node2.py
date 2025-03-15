import sys
import atexit
from models.arp_poisoning_node import ARPPoisoningNode


if __name__ == "__main__":
    # Create Node 1 with IP address 0x1A
    node = ARPPoisoningNode("N2", 0x2A, 50002, ["N2", "N3", "R2"], default_gateway="R2")

    # Initialize ARP table - Node2 knows about itself, Node3, and R2 in its network
    node.init_arp_table(
        {0x2A: "N2", 0x2B: "N3", 0x21: "R2"}  # Self  # Node3  # Router interface R2
    )

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
