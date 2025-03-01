import sys
import atexit
from models.node import Node

if __name__ == "__main__":
    # Create Node 3 with IP address 0x2B
    node = Node("N3", 0x2B, 50003, ["N2", "N3", "R2"], default_gateway="R2")

    # Initialize ARP table - Node3 knows about itself, Node2, and R2 in its network
    node.init_arp_table(
        {0x2B: "N3", 0x2A: "N2", 0x21: "R2"}  # Self  # Node2  # Router interface R2
    )

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
