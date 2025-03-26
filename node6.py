import sys
import atexit
from models.smurf_node import SmurfNode

if __name__ == "__main__":
    # Create Node 1 with IP address 0x1A
    node = SmurfNode("N6", 0x1B, 50010, ["N1", "N6", "R1"], default_gateway="R1")

    # Initialize ARP table - Node1 only knows about itself and R1 in its network
    node.init_arp_table(
        {0x1B: "N6", 0x1A: "N1", 0x11: "R1"}
    )  # Self  # Router interface R1

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
