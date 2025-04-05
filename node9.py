import sys
import atexit
from models.tcp_hijacking_node import TCPHijackingNode
from utils.routing import R2_ARP_TABLE, R2_NETWORK


if __name__ == "__main__":
    # Create Node 9 with IP address 0x2C
    node = TCPHijackingNode("N9", 0x2C, 50002, R2_NETWORK, default_gateway="R2")

    # Initialize ARP table - Node2 knows about itself, Node3, and R2 in its network
    node.init_arp_table(
        # Self  # Node3  # Router interface R2
        R2_ARP_TABLE
    )

    atexit.register(node.shutdown)

    print("\n====== TCP Hijacking Attack Node ======")
    print(
        "This node can automatically track TCP sessions and perform session hijacking attacks.\n"
    )
    print("Key commands:")
    print(
        "  sniff on                - Enable promiscuous mode to capture all traffic (auto-enables TCP tracking)"
    )
    print("  sessions                - Show all tracked TCP sessions")
    print("  session_data <id>       - View data exchanged in a session")
    print(
        "  hijack <id> as <ip> <msg> - Hijack session by impersonating client or server"
    )
    print("  continue <id> <msg>     - Continue sending messages in a hijacked session")
    print("  help                    - Show all available commands")
    print("\nTypical attack flow:")
    print(
        "1. Run 'sniff on' to monitor all traffic and automatically track TCP sessions"
    )
    print("2. Wait for TCP sessions to be established between other nodes")
    print("3. Use 'sessions' to view available sessions to attack")
    print(
        "4. Use 'hijack' to take over a session by simply specifying which IP to impersonate"
    )
    print(
        "   Example: 'hijack 1 as 2A Hello Server' to impersonate 0x2A (message goes to 0x2B)"
    )
    print(
        "   Example: 'hijack 1 as 2B I'm the server' to impersonate 0x2B (message goes to 0x2A)"
    )
    print("5. Use 'continue' to send additional messages in the hijacked session")
    print("   Example: 'continue 1 Give me all your secrets'\n")
    print("====================================\n")

    # Start the command interface
    node.run()

    sys.exit(0)
