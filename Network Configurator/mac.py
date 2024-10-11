from scapy.all import ARP, Ether, srp
import psutil
import ipaddress
import socket
import tkinter as tk
from tkinter import ttk
import paramiko
import os
import re

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

def ssh_connect_and_get_own_mac_table(hostname, username, password, command="display interface | no-more"):
    """SSH kapcsolat létrehozása és a MAC address tábla lekérdezése."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()

        with open(f"own_mac_address_table-{hostname}.txt", "w") as file:
            file.write(output)

        print(f"MAC address tábla sikeresen mentve: mac_address_table-{hostname}.txt")
        ssh.close()
    except Exception as e:
        print(f"Hiba történt az SSH kapcsolat létrehozása során: {e}")

def ssh_connect_and_get_mac_table(hostname, username, password, command="display mac-address table"):
    """SSH kapcsolat létrehozása és a MAC address tábla lekérdezése."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()

        with open(f"mac_address_table-{hostname}.txt", "w") as file:
            file.write(output)

        print(f"MAC address tábla sikeresen mentve: mac_address_table-{hostname}.txt")
        ssh.close()
    except Exception as e:
        print(f"Hiba történt az SSH kapcsolat létrehozása során: {e}")

def start_ssh_connection():
    """Indítja az SSH kapcsolatot az összes eszközhöz és kimenti a MAC address táblákat."""
    username = ssh_username_entry.get()
    password = ssh_password_entry.get()
    scanned_devices = scan_devices()

    for device in scanned_devices:
        hostname = device['ip']
        ssh_connect_and_get_own_mac_table(hostname, username, password)
        ssh_connect_and_get_mac_table(hostname, username, password)

    own_mac_tables()

def extract_mac_addresses_from_file(filepath):
    """Kivonja a MAC címeket a megadott fájlból."""
    mac_addresses = set()
    with open(filepath, 'r') as file:
        for line in file:
            # MAC címek keresése reguláris kifejezéssel
            matches = re.findall(r'([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})', line, re.IGNORECASE)
            for match in matches:
                mac_addresses.add(match)  # Hozzáadás halmazhoz
    return mac_addresses

def load_mac_addresses_from_directory(directory):
    """Beolvassa az összes .txt fájlt a megadott mappából, és a MAC címeket IP címekhez rendeli."""
    own_ip_mac_dict = {}
    ip_mac_dict = {}
    
    for filename in os.listdir(directory):
        if filename.endswith('.txt') and filename[:3] == "own":
            # IP cím kinyerése a fájlnévből (hostname.txt -> hostname)
            full_name = str(filename[:-4])  # eltávolítjuk a .txt kiterjesztést
            ip_address_name =  full_name.split('-')[1] # itt használhatod a tényleges IP cím kinyerését, ha szükséges
            
            # MAC címek kinyerése
            mac_addresses = extract_mac_addresses_from_file(os.path.join(directory, filename))
            
            # Szótár frissítése
            if mac_addresses:
                own_ip_mac_dict[ip_address_name] = mac_addresses
        elif filename.endswith('.txt') and filename[:3] != "own":
            # IP cím kinyerése a fájlnévből (hostname.txt -> hostname)
            full_name = str(filename[:-4])  # eltávolítjuk a .txt kiterjesztést
            ip_address_name =  full_name.split('-')[1] # itt használhatod a tényleges IP cím kinyerését, ha szükséges
            
            # MAC címek kinyerése
            mac_addresses = extract_mac_addresses_from_file(os.path.join(directory, filename))
            
            # Szótár frissítése
            if mac_addresses:
                ip_mac_dict[ip_address_name] = mac_addresses

    return own_ip_mac_dict, ip_mac_dict

def own_mac_tables():
    own_mac_address, mac_address_table = load_mac_addresses_from_directory("./")
    print(f"{own_mac_address}\n\n\n{mac_address_table}")

def main():
    """A grafikus felület és a fő logika elindítása."""
    global root, table_frame, canvas, interface_combobox, ssh_username_entry, ssh_password_entry, scanned_devices
    
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

    table_frame = tk.Frame(canvas)
    canvas.create_window((0, 0), window=table_frame, anchor='nw')

    scan_button = tk.Button(root, text="Eszközök beolvasása", command=scan_devices)
    scan_button.pack(pady=10)

    ssh_username_label = tk.Label(root, text="Felhasználónév:")
    ssh_username_label.pack(pady=5)
    ssh_username_entry = tk.Entry(root)
    ssh_username_entry.pack(pady=5)

    ssh_password_label = tk.Label(root, text="Jelszó:")
    ssh_password_label.pack(pady=5)
    ssh_password_entry = tk.Entry(root, show="*")
    ssh_password_entry.pack(pady=5)

    ssh_button = tk.Button(root, text="MAC tábla lekérdezése", command=start_ssh_connection)
    ssh_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
