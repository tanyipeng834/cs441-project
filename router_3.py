import sys
import atexit
from models.router import Router, RouterNode
from models.ip_packet import IPPacket
from utils.routing import R7_ARP_TABLE, R7_NETWORK,R8_ARP_TABLE,R8_NETWORK

if __name__ == "__main__":
    # Create router with two nodes: R1 and R2
    # Node R1: connected to network with N1
    # Node R2: connected to network with N2 and N3

    # Create router nodes first
    r7_node = RouterNode("R7", 0x71, 50018, R7_NETWORK)
    r8_node = RouterNode("R8", 0x81, 50019, R8_NETWORK)
    

    # Create router with the nodes
    router = Router([r7_node,r8_node])
    r7_node.init_network_ips([0x61])
    r7_node.init_arp_table(R7_ARP_TABLE)

    # Initialize network IPs for node R1
    r8_node.init_network_ips([0x8A])  # N1's IP is 0x1A
    # Initialize ARP table for node R1
    r8_node.init_arp_table(R8_ARP_TABLE)

   

    # Initialize routing table
    router.init_routing_table(
        {
            0x11 : r7_node,
            0x1A:  r7_node,
            0x1B : r7_node,
            0x1C : r7_node,
            0x1D : r7_node,
            0x1E : r7_node,
            0x1F : r7_node,
            0x21 : r7_node,
            0x2A:  r7_node,  
            0x2B:  r7_node,
            0x2C : r7_node,
            0x31 : r7_node,
            0x41 : r7_node,
            0x51:  r7_node,
            0x5A:  r7_node,
            0x61:  r7_node,
            0x8A : r8_node,


        }
    )

    # Register shutdown function to clean up on exit
    atexit.register(router.shutdown)

    atexit.register(router.shutdown)

    print("Router started with nodes R7 (0x71) and R8 (0x81)")
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
                print("  R7 node:")
                for ip, mac in r7_node.arp_table.items():
                    print(f"    0x{ip:02X} -> {mac}")
                print("  R2 node:")
                for ip, mac in r8_node.arp_table.items():
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
                    source_ip = r7_node.ip_address

                    dest_ip = int(dest_ip, 16)
                    if dest_ip not in r7_node.network_ips:
                        print(" Network not available")
                    else:
                        ip_packet = IPPacket(source_ip, dest_ip, 17, f"IKE{mode}")
                        
                        r7_node.send_ip_packet(ip_packet, r7_node.arp_table[dest_ip])
                        router.mutual_key_exchange(int(mode), dest_ip)

                else:
                    if len(args) == 1:
                        ip_packet = IPPacket(source_ip, dest_ip, 17, "IKE")
                        r7_node.send_ip_packet(ip_packet, r7_node.arp_table[dest_ip])
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
