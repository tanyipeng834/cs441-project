from Node import Node
from Network import Network 
class Main:
   

 
    

    if __name__ == "__main__":
        lan_1 = Network()
        lan_2 = Network()
        node1 = Node('N1',50001,lan_1)
        node2 = Node('N2',50002,lan_2)
        node3 = Node('N3', 50003,lan_2)
        router_interface_1 = Node('R1',50004,lan_1)
        router_interface_2 = Node('R2' ,50005,lan_2)
        lan_1.add_node(node1)
        lan_1.add_node(router_interface_1)
        lan_2.add_node(node2)
        lan_2.add_node(router_interface_2)
        lan_2.add_node(node3)
        node2.send_frame('N3','Hello World, Coming from N2')






