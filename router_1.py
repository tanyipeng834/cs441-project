import sys
import atexit
from models.router import Router, RouterNode
from models.ip_packet import IPPacket
from utils.routing import R1_ARP_TABLE, R1_NETWORK,R2_ARP_TABLE,R2_NETWORK,R3_NETWORK,R3_ARP_TABLE


if __name__ == "__main__":
    # Create router with two nodes: R1 and R2
    # Node R1: connected to network with N1
    # Node R2: connected to network with N2 and N3

    # Create router nodes first
    r1_node = RouterNode("R1", 0x11, 50012, R1_NETWORK)
    r2_node = RouterNode("R2", 0x21, 50013, R2_NETWORK)
    r3_node = RouterNode("R3", 0x31, 50014, R3_NETWORK)

    # Create router with the nodes
    router = Router([r1_node, r2_node, r3_node])

    # Initialize network IPs for node R1
    r1_node.init_network_ips([0x1A,0x1B,0x1C,0x1D,0x1E,0x1F])  # N1's IP is 0x1A
    # Initialize ARP table for node R1
    r1_node.init_arp_table(R1_ARP_TABLE)

    # Initialize network IPs for node R2
    r2_node.init_network_ips([0x2A, 0x2B,0x2C])  # N2 and N3's IPs
    # Initialize ARP table for node R2
    r2_node.init_arp_table(
       R2_ARP_TABLE
    )
    r3_node.init_network_ips([0x41])

    # ROUTE to all other 

    r3_node.init_arp_table(
        R3_ARP_TABLE
        )  # Self-reference

    # Initialize routing table
    router.init_routing_table(
        {
            0x1A: r1_node,
            0x1B : r1_node,
            0x1C : r1_node,
            0x1D : r1_node,
            0x1E : r1_node,
            0x1F : r1_node,
            0x2A: r2_node,  
            0x2B: r2_node,
            0x2C : r2_node,
            0x41: r3_node,
            0x5A: r3_node,
            0x51 :r3_node,
            0x61 :r3_node,
            0x71 : r3_node,
            0X81 : r3_node,
            0x8A : r3_node,
        }
    )

    # Register shutdown function to clean up on exit
    atexit.register(router.shutdown)

    print("Router started with nodes R1 (0x11) and R2 (0x21) and R3 (0x31)")
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
                print("  R1 node:")
                for ip, mac in r1_node.arp_table.items():
                    print(f"    0x{ip:02X} -> {mac}")
                print("  R2 node:")
                for ip, mac in r2_node.arp_table.items():
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
                    source_ip = r3_node.ip_address

                    dest_ip = int(dest_ip, 16)
                    if dest_ip not in r3_node.network_ips:
                        print(" Network not available")
                    else:
                        ip_packet = IPPacket(source_ip, dest_ip, 17, f"IKE{mode}")
                        r3_node.send_ip_packet(ip_packet, r3_node.arp_table[dest_ip])
                        router.mutual_key_exchange(int(mode), dest_ip)

                else:
                    if len(args) == 1:
                        ip_packet = IPPacket(source_ip, dest_ip, 17, "IKE")
                        r3_node.send_ip_packet(ip_packet, r3_node.arp_table[dest_ip])
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
