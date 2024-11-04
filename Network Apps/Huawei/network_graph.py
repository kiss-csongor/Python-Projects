from scapy.all import ARP, Ether, srp
import psutil
import ipaddress
import socket
import paramiko
import threading

import tkinter as tk
from tkinter import ttk

import os
import re
import time

import networkx as nx
import matplotlib.pyplot as plt
from PIL import Image

device_types = {}
device_list = {}
devices_mac_addresses = {}
edges = []
hostname_with_ip_address = {}

def get_friendly_interfaces():
    """Az eszköz interfész listájának létrehozása IP-címekkel, alhálózatokkal és alhálózati maszkokkal."""
    friendly_interfaces = []

    for iface_name, iface_info in psutil.net_if_addrs().items():
        try:
            for addr in iface_info:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask
                    subnet = calculate_subnet(ip, netmask)
                    friendly_interfaces.append(f"{iface_name} - {ip} - {subnet} - {netmask}")
        except Exception as e:
            friendly_interfaces.append(f"{iface_name} - Error: {e}")

    return friendly_interfaces

def arp_scan(subnet, interface):
    """Felfedezi az alhálózaton lévő eszközöket az adott interfészen."""
    arp_request = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=2, verbose=False, iface=interface.split(" - ")[0])[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def calculate_subnet(ip, netmask):
    """Alhálózat számítása IP-cím és netmask alapján."""
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    cidr = netmask_to_cidr(netmask)
    return f"{network.network_address}/{cidr}"

def netmask_to_cidr(netmask):
    """A netmask átalakítása CIDR formátumba."""
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))

def create_table(devices):
    """Táblázat létrehozása az eszközökkel."""
    global table_frame
    for widget in table_frame.winfo_children():
        widget.destroy()

    tk.Label(table_frame, text="IP cím", font=('bold', 12)).grid(row=0, column=0, padx=10, pady=10)
    tk.Label(table_frame, text="MAC cím", font=('bold', 12)).grid(row=0, column=1, padx=10, pady=10)

    for index, device in enumerate(devices, start=1):
        tk.Label(table_frame, text=device['ip']).grid(row=index, column=0, padx=10, pady=5)
        tk.Label(table_frame, text=device['mac']).grid(row=index, column=1, padx=10, pady=5)

    table_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))

def scan_devices_thread():
    """Scan devices in a separate thread."""
    threading.Thread(target=scan_devices).start()

def scan_devices():
    """Eszközök beolvasása a kiválasztott interfészről."""
    global table_frame
    selected_interface = interface_combobox.get()
    ip = ""
    netmask = ""
    
    try:
        parts = selected_interface.split(" - ")
        ip = parts[1]
        netmask = parts[3]
    except IndexError:
        print("Hiba az interfész adatok beolvasásakor.")
        return

    subnet = calculate_subnet(ip, netmask)
    devices = arp_scan(subnet, selected_interface)
    create_table(devices)
    return devices

def send_command(shell, command):
    """Parancs elküldése az interaktív SSH session-ön keresztül.""" 
    try:
        shell.send(command + "\n")
        time.sleep(1)
        output = ""
        while not shell.recv_ready():
            continue

        output += shell.recv(65535).decode()

        root.after(500)
        
        while shell.recv_ready():
            output += shell.recv(65535).decode()

        return output.strip()
    except Exception as e:
        return f"Hiba a parancskiadás során: {e}"

def extract_from_prompt(text):
    """Kinyeri a hosztneveket a megadott szövegből"""
    pattern = r'<(.*?)>|[(.*?)]'
    hostname_set = set(re.findall(pattern, text))
    hostname_string = ''.join(hostname_set)

    return hostname_string

def ssh_connect_and_get_lldp_table(ip_address, username, password):
    """SSH kapcsolat létrehozása és a MAC address tábla lekérdezése."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, username=username, password=password)
        shell = ssh.invoke_shell()

        text = send_command(shell, "\n")
        hostname = extract_from_prompt(text)

        command="screen-length 0 temporary\ndisplay lldp neighbor"
        output = send_command(shell, command)
        with open(f"lldp_table&{ip_address}={hostname}.txt", "w") as file:
            file.write(output)
        print(f"LLDP kimenet sikeresen mentve: lldp_table&{ip_address}={hostname}.txt")

        ssh.close()
        return "sw"
    except Exception as e:
        print(f"Hiba történt az SSH kapcsolat létrehozása során: {e}")
        return "pc"

def start_ssh_connection_thread():
    """SSH kapcsolat indítása külön szálon."""
    threading.Thread(target=start_ssh_connection).start()

def start_ssh_connection():
    """Indítja az SSH kapcsolatot az összes eszközhöz és kimenti az LLDP táblákat."""
    username = ssh_username_entry.get() or "administrator"
    password = ssh_password_entry.get() or "Labor123-"
    scanned_devices = scan_devices()

    counter_sw = 1
    counter_pc = 1

    for device in scanned_devices:
        hostname = device['ip']
        device_list[device['ip']] = device['mac']
        device_type = ssh_connect_and_get_lldp_table(hostname, username, password)
        if device_type == "sw":
            device_types[f"{device_type}-{counter_sw}"] = device['ip']
            counter_sw += 1
        elif device_type == "pc":
            device_types[f"{device_type}-{counter_pc}"] = device['ip']
            counter_pc += 1

    load_mac_addresses_from_directory("./")
    edge_summary(devices_mac_addresses, device_list)
    draw_network_graph(device_types, edges)

def extract_mac_addresses_from_file(filepath):
    """Kinyeri a MAC címeket a megadott fájlból."""
    mac_addresses = set()
    with open(filepath, 'r') as file:
        for line in file:
            # MAC címek keresése reguláris kifejezéssel
            matches = re.findall(r'([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})', line, re.IGNORECASE)
            for match in matches:
                mac_addresses.add(match)  # Hozzáadás halmazhoz
    mac_addresses_list = list(mac_addresses)
    return mac_addresses_list

def load_mac_addresses_from_directory(directory):
    """Beolvassa az összes .txt fájlt a megadott mappából, és a MAC címeket IP címekhez rendeli."""
    
    for filename in os.listdir(directory):
        if filename.endswith('.txt') and filename[:3]:
            # IP cím kinyerése a fájlnévből (hostname.txt -> hostname)
            full_name = str(filename[:-4])  # eltávolítjuk a .txt kiterjesztést
            ip_and_hostname = full_name.split('&')[1] 
            ip_address_name = ip_and_hostname.split('=')[0] # fájlnévből kinyerjük az ip címet
            hostname = ip_and_hostname.split('=')[1] # fájlnévből kinyerjük az hosztnevet
            hostname_with_ip_address[hostname] = ip_address_name # hozzáadjuk egy szótárhoz az adott párosokat
            mac_addresses_list = []

            if full_name.split('&')[0] == "lldp_table":
                # MAC címek kinyerése
                mac_addresses_list = extract_mac_addresses_from_file(os.path.join(directory, filename))
            # Szótár frissítése
            if mac_addresses_list:
                devices_mac_addresses[ip_address_name] = mac_addresses_list

import networkx as nx
import matplotlib.pyplot as plt
from PIL import Image

def draw_network_graph(device_types, edges):
    # Ikonok elérési útvonalai
    icons = {
        "pc": "#images/pc.png",  # PC
        "sw": "#images/switch.png",  # Switch
        "r": "#images/router.png",  # Router
    }
    
    # Képek betöltése és hibakezelés
    images = {}
    for key, path in icons.items():
        try:
            images[key] = Image.open(path)
        except FileNotFoundError:
            print(f"Hiba: A(z) '{path}' fájl nem található.")
            images[key] = None  # Beállítunk None-t, ha a fájl nem található


    # Gráf létrehozása
    G = nx.Graph()
    # Csomópontok hozzáadása megfelelő képekkel
    for device_type, ip in device_types.items():
        device_key = device_type.split('-')[0]  # A 'pc', 'sw' vagy 'r' prefix
        if device_key in images and images[device_key] is not None:
            G.add_node(ip, image=images[device_key])
        else:
            print(f"A {device_key} eszközhöz nem található kép az IP címmel: {ip}")

    # Élek hozzáadása
    for edge in edges:
        src, dest = edge.split('-')[0], edge.split('-')[1]
        G.add_edge(src, dest)

    # Elrendezés meghatározása
    pos = nx.spring_layout(G, seed=42)

    # Ábra létrehozása
    fig, ax = plt.subplots()

    # Élek kirajzolása
    nx.draw_networkx_edges(G, pos, ax=ax)

    # Funkció a képek és címkék hozzáadására a csomópontokhoz
    def add_images_and_labels_to_nodes(G, pos, ax):
        tr_figure = ax.transData.transform
        tr_axes = fig.transFigure.inverted().transform
        
        icon_size = (ax.get_xlim()[1] - ax.get_xlim()[0])
        if len(G.nodes) >= 4:
            icon_size = icon_size * (0.1 / len(G.nodes))
        elif len(G.nodes) == 3:
            icon_size = icon_size * 0.06
        elif len(G.nodes) == 2:
            icon_size = icon_size * 0.03
        icon_center = icon_size / 2
        
        for node in G.nodes:
            xf, yf = tr_figure(pos[node])
            xa, ya = tr_axes((xf, yf))
            a = plt.axes([xa - icon_center, ya - icon_center, icon_size, icon_size])
            if 'image' in G.nodes[node]:
                a.imshow(G.nodes[node]["image"])
                a.axis("off")
                # IP cím címke hozzáadása az ikon fölé
                ax.text(pos[node][0], pos[node][1] + 0.1, node, fontsize=12, ha='center')
            else:
                print(f"A {node} csomópontnak nincs 'image' attribútuma.")  # Hibakeresési sor

    # Képek és címkék hozzáadása a gráf csomópontjaihoz
    add_images_and_labels_to_nodes(G, pos, ax)

    plt.show()

def edge_summary(mac_addresses, devices):
    for ip, macs in mac_addresses.items(): 
        for mac in macs:
            matching_ip = next((key for key, value in devices.items() if value.replace(":", "") == mac.replace("-","")), None)
            # Ellenőrizzük, hogy találtunk-e matching_ip-t
            if matching_ip is None:
                # Ha nem találunk egyezést, emeljük a kivételt
                continue
            edge = f"{min(ip, matching_ip)}-{max(ip, matching_ip)}"
            if edge not in edges and matching_ip != ip:
                edges.append(edge)

def main():
    """A grafikus felület és a fő logika elindítása."""
    global root, table_frame, canvas, interface_combobox, ssh_username_entry, ssh_password_entry
    
    root = tk.Tk()
    root.title("Hálózati Eszközök")
    root.geometry("800x600")

    interface_label = tk.Label(root, text="Interfész:")
    interface_label.pack(pady=10)

    interface_combobox = ttk.Combobox(root, values=get_friendly_interfaces(), width=65)
    interface_combobox.pack(pady=5)
    interface_combobox.current(0)

    canvas = tk.Canvas(root)
    canvas.pack(fill=tk.BOTH, expand=True)

    # Center the table_frame in the canvas
    table_frame = tk.Frame(canvas)
    canvas.create_window((400, 0), window=table_frame, anchor='n')  # 400 a canvas szélességének fele

    scan_button = tk.Button(root, text="Eszközök beolvasása", command=scan_devices_thread)
    scan_button.pack(pady=10)

    ssh_username_label = tk.Label(root, text="Felhasználónév:")
    ssh_username_label.pack(pady=5)
    ssh_username_entry = tk.Entry(root)
    ssh_username_entry.pack(pady=5)

    ssh_password_label = tk.Label(root, text="Jelszó:")
    ssh_password_label.pack(pady=5)
    ssh_password_entry = tk.Entry(root, show="*")
    ssh_password_entry.pack(pady=5)

    ssh_button = tk.Button(root, text="Hálózati ábra kirajzolása", command=start_ssh_connection_thread)
    ssh_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()