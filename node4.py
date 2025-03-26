import sys
import atexit
from models.node import Node

if __name__ == "__main__":
    # Create Node 1 with IP address 0x1A
    node = Node("N4", 0x5A, 50009, ["N4", "R5"], default_gateway="R5")

    # Initialize ARP table - Node1 only knows about itself and R1 in its network
    node.init_arp_table(
        {0x5A: "N4", 0x51: "R5", 0x1A: "R5"}
    )  # Self  # Router interface R1

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
