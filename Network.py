class Network:
    def __init__(self):
        self.nodes = []

    def add_node(self, node):
        self.nodes.append(node)

    # broadcast to all nodes
    def get_nodes(self):
        return self.nodes