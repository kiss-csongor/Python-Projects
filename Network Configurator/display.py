import networkx as nx
import matplotlib.pyplot as plt
from PIL import Image
import matplotlib.offsetbox as offsetbox

def draw_network_graph(devices, edges):
    # Image paths for the icons
    icons = {
        "pc": "images/pc.png",    # PC
        "sw": "images/switch.png",  # Switch
        "r": "images/router.png"    # Router
    }
    # Load images
    images = {key: Image.open(path) for key, path in icons.items()}

    # Create a graph
    G = nx.Graph()
    # Add nodes with corresponding images
    for device_type, ip in devices.items():
        device_key = device_type.split('-')[0]  # Get the 'pc', 'sw', or 'r' prefix
        if device_key in images:
            G.add_node(ip, image=images[device_key])
    # Add edges
    for src, dest in edges.items():
        G.add_edge(src, dest)

    # Define layout
    pos = nx.spring_layout(G, seed=42)

    # Create the plot
    fig, ax = plt.subplots()

    # Draw edges
    nx.draw_networkx_edges(G, pos, ax=ax)

    # Function to add images at node positions and IP labels above icons
    def add_images_and_labels_to_nodes(G, pos, ax):
        tr_figure = ax.transData.transform
        tr_axes = fig.transFigure.inverted().transform
        
        icon_size = (ax.get_xlim()[1] - ax.get_xlim()[0])
        icon_size = icon_size * (0.2 / len(G.nodes)) if len(G.nodes) >= 4 else icon_size * 0.2
        icon_center = icon_size / 2.0
        
        for node in G.nodes:
            xf, yf = tr_figure(pos[node])
            xa, ya = tr_axes((xf, yf))
            a = plt.axes([xa - icon_center, ya - icon_center, icon_size, icon_size])
            a.imshow(G.nodes[node]["image"])
            a.axis("off")
            # Add IP address label above the icon
            ax.text(pos[node][0], pos[node][1] + 0.1, node, fontsize=12, ha='center')

    # Add images and labels to the graph nodes
    add_images_and_labels_to_nodes(G, pos, ax)

    plt.show()

# Example usage
devices = {
    "pc-1": "192.168.100.100",
    "r-1": "192.168.100.50",
    "sw-1": "192.168.100.1"
}

edges = {
    "192.168.100.100": "192.168.100.50",
    "192.168.100.50": "192.168.100.1"
}

draw_network_graph(devices, edges)
