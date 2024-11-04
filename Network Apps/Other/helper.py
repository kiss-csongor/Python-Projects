import networkx as nx
import matplotlib.pyplot as plt
from PIL import Image

mac_addresses = {
    "192.168.0.1": ["7C10C91FFF02", "7C10C91FFF04", "7C10C91FFF05"],
    "192.168.0.2": ["7C10C91FFF01", "7C10C91FFF03", "7C10C91FFF06", "7C10C91FFF07"],
    "192.168.0.3": ["7C10C91FFF02", "7C10C91FFF08"],
}

devices = {
    "192.168.0.1": '7C10C91FFF01',
    "192.168.0.2": '7C10C91FFF02',
    "192.168.0.3": '7C10C91FFF03',
    "192.168.0.4": '7C10C91FFF04',
    "192.168.0.5": '7C10C91FFF05',
    "192.168.0.6": '7C10C91FFF06',
    "192.168.0.7": '7C10C91FFF07',
    "192.168.0.8": '7C10C91FFF08',
}

device_types = {
    "sw-1":"192.168.0.1",
    "sw-2":"192.168.0.2",
    "sw-3":"192.168.0.3",
    "pc-1":"192.168.0.4",
    "pc-2":"192.168.0.5",
    "pc-3":"192.168.0.6",
    "pc-4":"192.168.0.7",
    "pc-5":"192.168.0.8",
}

edges = []

def draw_network_graph(device_types, edges):
    # Image paths for the icons
    icons = {
        "pc": "images/pc.png", # PC
        "sw": "images/switch.png", # Switch
        "r": "images/router.png" # Router
    }
    # Load images
    images = {key: Image.open(path) for key, path in icons.items()}
    print(images)

    # Create a graph
    G = nx.Graph()
    # Add nodes with corresponding images
    for device_type, ip in device_types.items():
        device_key = device_type.split('-')[0]  # Get the 'pc', 'sw', or 'r' prefix
        if device_key in images:
            G.add_node(ip, image=images[device_key])
    # Add edges
    for edge in edges:
        src, dest = edge.split('-')[0], edge.split('-')[1]
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
        icon_size = icon_size * (0.3 / len(G.nodes)) if len(G.nodes) >= 4 else icon_size * 0.1
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

def edge_summary(mac_addresses, devices):
    for ip, macs in mac_addresses.items():
        id = 0
        for mac in macs:
            matching_ip = next((key for key, value in devices.items() if value == mac), None)
            if f"{min(ip, matching_ip)}-{max(ip, matching_ip)}" not in edges:
                edges.append(f"{min(ip, matching_ip)}-{max(ip, matching_ip)}")

edge_summary(mac_addresses, devices)
draw_network_graph(device_types, edges)