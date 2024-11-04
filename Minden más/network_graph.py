import networkx as nx
import matplotlib.pyplot as plt

# Eszközök és kapcsolatok
devices = [
    {'ip': '192.168.1.2', 'mac': '00:11:22:33:44:55'},
    {'ip': '192.168.1.3', 'mac': '66:77:88:99:AA:BB'},
]
switch_ip = '192.168.1.1'

# Gráf létrehozása
G = nx.Graph()
G.add_node(switch_ip)

for device in devices:
    G.add_node(device['ip'])
    G.add_edge(switch_ip, device['ip'])  # Kapcsolat a switch és az eszköz között

# Gráf megjelenítése
nx.draw(G, with_labels=True)
plt.show()
