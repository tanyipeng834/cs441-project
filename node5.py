import sys
import atexit
from models.node import Node

if __name__ == "__main__":
    # Create Node 1 with IP address 0x1A
    node = Node("N5", 0x8A, 50011, ["N5", "R8"], default_gateway="R8")

    # Initialize ARP table - Node1 only knows about itself and R1 in its network
    node.init_arp_table(
        {0x8A: "N5", 0x81: "R8"}
    )  # Self  # Router interface R1

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)