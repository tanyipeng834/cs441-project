import sys
import atexit
from models.node import Node

if __name__ == "__main__":
    # Create Node 1 with IP address 0x1A
    node = Node("N1", 0x1A, 50001, ["N1", "R1"], default_gateway="R1")
    
    # Initialize ARP table - Node1 only knows about itself and R1 in its network
    node.init_arp_table({
        0x1A: "N1",  # Self
        0x11: "R1"   # Router interface R1
    })
    
    atexit.register(node.shutdown)

    print("Node1 started with IP 0x1A (26)")
    print("Available commands:")
    print("  <destination> <message> - Send raw Ethernet frame (original format)")
    print("  ping <ip_hex> <message> - Send a ping to the specified IP")
    print("  arp - Display the ARP table")
    print("  q - Exit")

    try:
        while True:
            user_input = input("N1>> ").strip()
            if user_input.lower() == "q":
                print("Exiting...")
                break
            if not user_input:
                continue

            parts = user_input.split(" ", 1)
            
            if parts[0].lower() == "ping":
                if len(parts) < 2:
                    print("Invalid input. Usage: ping <ip_hex> <message>")
                    continue
                
                ping_parts = parts[1].split(" ", 1)
                if len(ping_parts) < 2:
                    print("Invalid input. Usage: ping <ip_hex> <message>")
                    continue
                
                try:
                    # Convert hex string to integer
                    dest_ip = int(ping_parts[0], 16)
                    message = ping_parts[1]
                    
                    # Send ping packet
                    node.send_ip_packet(dest_ip, Node.PROTOCOL_PING, message)
                    print(f"Ping sent to 0x{dest_ip:02X} with message: {message}")
                except ValueError:
                    print("Invalid IP address. Please enter a valid hex value (e.g., 2A)")
                
            elif parts[0].lower() == "arp":
                print("ARP Table:")
                for ip, mac in node.arp_table.items():
                    print(f"  0x{ip:02X} -> {mac}")
            
            elif parts[0] in Node.VALID_DESTINATION:
                # Original frame-sending format
                if len(parts) != 2:
                    print("Invalid input. Please provide both destination and data.")
                    continue
                
                destination = parts[0]
                data = parts[1]
                
                node.send_frame(destination, data)
                print(f"Ethernet frame sent to {destination} with data: {data}")
                    
            else:
                print("Invalid command or destination.")
                print("Available commands: ping, arp, q")
                print("Or send raw frame: <destination> <message>")
                
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Exiting...")
    finally:
        node.shutdown()
        sys.exit(0)