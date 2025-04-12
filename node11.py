import sys
import atexit
from models.traceback_node import TracebackNode
from utils.routing import R8_ARP_TABLE, R8_NETWORK

if __name__ == "__main__":
    # Create Node 1 with IP address 0x1A
    node = TracebackNode("NB", 0x8A, 50011, R8_NETWORK, default_gateway="R8")

    # Initialize ARP table - Node1 only knows about itself and R1 in its network
    node.init_arp_table(R8_ARP_TABLE)

    atexit.register(node.shutdown)

    # Start the command interface
    node.run()

    sys.exit(0)
