import sys
import atexit
from models.router import Router, RouterNode
from models.ip_packet import IPPacket
from utils.routing import (
    R4_ARP_TABLE,
    R4_NETWORK,
    R5_ARP_TABLE,
    R5_NETWORK,
    R6_NETWORK,
    R6_ARP_TABLE,
)

if __name__ == "__main__":
    # Create router with two nodes: R1 and R2
    # Node R1: connected to network with N1
    # Node R2: connected to network with N2 and N3

    # Create router nodes first
    r4_node = RouterNode("R4", 0x41, 50015, R4_NETWORK)
    r5_node = RouterNode("R5", 0x51, 50016, R5_NETWORK)

    r6_node = RouterNode("R6", 0x61, 50017, R6_NETWORK)

    # Create router with the nodes
    router = Router([r4_node, r5_node, r6_node])
    r4_node.init_network_ips([0x31])
    r4_node.init_arp_table(R4_ARP_TABLE)

    # Initialize network IPs for node R1
    r5_node.init_network_ips([0x5A])  # N1's IP is 0x1A
    # Initialize ARP table for node R1
    r5_node.init_arp_table(R5_ARP_TABLE)

    r6_node.init_network_ips([0x71])  # N1's IP is 0x1A
    r6_node.init_arp_table(R6_ARP_TABLE)

    # Initialize network IPs for node R2

    # Initialize routing table
    router.init_routing_table(
        {
            0x11: r4_node,
            0x1A: r4_node,
            0x1B: r4_node,
            0x1C: r4_node,
            0x1D: r4_node,
            0x1E: r4_node,
            0x1F: r4_node,
            0x21: r4_node,
            0x2A: r4_node,
            0x2B: r4_node,
            0x2C: r4_node,
            0x5A: r5_node,
            0x71: r6_node,
            0x81: r6_node,
            0x8A: r6_node,
        }
    )

    # Register shutdown function to clean up on exit
    atexit.register(router.shutdown)

    atexit.register(router.shutdown)

    print("Router started with nodes R4 (0x41) and R5 (0x51) and R6 (0x61)")
    print("Available commands:")
    print("  routes - Display the routing table")
    print("  ipsec <mode> <ip> - Configure ipsec tunnel with another network")
    print("  ipsec off - Configure ipsec tunnel with another network")
    print("  arp - Display the ARP tables")
    print("  q - Exit")

    try:
        # Keep the main thread alive
        while True:
            user_input = input("Router>> ")
            parts = user_input.split(" ")
            command = parts[0]
            args = parts[1:]
            if command.lower() == "q":
                print("Shutting down router...")
                break
            elif command.lower() == "routes":
                print("Routing table:")
                for ip, node in router.routing_table.items():
                    print(f"  0x{ip:02X} -> {node.mac_address}")
            elif command.lower() == "arp":
                print("ARP tables:")
                print("  R4 node:")
                for ip, mac in r4_node.arp_table.items():
                    print(f"    0x{ip:02X} -> {mac}")
                print("  R5 node:")
                for ip, mac in r5_node.arp_table.items():
                    print(f"    0x{ip:02X} -> {mac}")
                print("  R6 node:")
                for ip, mac in r6_node.arp_table.items():
                    print(f"    0x{ip:02X} -> {mac}")
            elif command.lower() == "ipsec":

                if len(args) == 2:
                    mode = args[0].upper()
                    if mode == "AH":
                        mode = 0
                    elif mode == "ESP":
                        mode = 1
                    else:
                        print("Mode must be either AH or ESP")
                        break
                    dest_ip = args[1]
                    # used with udp
                    source_ip = r4_node.ip_address

                    dest_ip = int(dest_ip, 16)
                    if dest_ip not in r4_node.network_ips:
                        print(" Network not available")
                    else:
                        ip_packet = IPPacket(source_ip, dest_ip, 17, f"IKE{mode}")
                        r4_node.send_ip_packet(ip_packet, r4_node.arp_table[dest_ip])
                        router.mutual_key_exchange(int(mode), dest_ip)

                else:
                    if len(args) == 1:
                        ip_packet = IPPacket(source_ip, dest_ip, 17, "IKE")
                        r4_node.send_ip_packet(ip_packet, r4_node.arp_table[dest_ip])
                        router.kill_tunnel()
                    else:
                        print(
                            "Error: Invalid command syntax. Usage: ipsec <mode> <ip> "
                        )

            else:
                print("Unknown command. Available commands: routes, arp, q , ipsec")
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Shutting down router...")
    finally:
        router.shutdown()
        sys.exit(0)
