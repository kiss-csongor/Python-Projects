from scapy.all import ARP, Ether, srp
import psutil
import ipaddress
import socket
import tkinter as tk
from tkinter import ttk

def get_friendly_interfaces():
    """Az eszköz interfész listájának létrehozása IP-címekkel, alhálózatokkal és alhálózati maszkokkal."""
    friendly_interfaces = []

    # Minden interfész átvizsgálása
    for iface_name, iface_info in psutil.net_if_addrs().items():
        try:
            # Keresünk egy IPv4 címet
            for addr in iface_info:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask
                    # Alhálózat kiszámítása
                    subnet = calculate_subnet(ip, netmask)
                    # IP-cím, alhálózat és netmask megjelenítése
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
    cidr = netmask_to_cidr(netmask)  # CIDR számítása
    return f"{network.network_address}/{cidr}"

def netmask_to_cidr(netmask):
    """A netmask átalakítása CIDR formátumba."""
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))

def create_table(devices):
    """Táblázat létrehozása az eszközökkel."""
    global table_frame  # Jelentsd ki globálisként
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
    global table_frame  # Jelentsd ki globálisként
    selected_interface = interface_combobox.get()
    
    # A kiválasztott interfész IP-címének és netmaskjának kinyerése
    ip = ""
    netmask = ""
    
    try:
        parts = selected_interface.split(" - ")
        ip = parts[1]
        netmask = parts[3]
    except IndexError:
        print("Hiba az interfész adatok beolvasásakor.")
        return

    # Alhálózat kiszámítása
    subnet = calculate_subnet(ip, netmask)
    
    # Eszközök beolvasása az alhálózaton
    devices = arp_scan(subnet, selected_interface)
    create_table(devices)

def main():
    """A grafikus felület és a fő logika elindítása."""
    global root, table_frame, canvas, interface_combobox
    
    # Grafikus felület létrehozása
    root = tk.Tk()
    root.title("Hálózati Eszközök")
    root.geometry("800x600")

    # Interfész kiválasztása
    interface_label = tk.Label(root, text="Interfész:")
    interface_label.pack(pady=10)

    # Interfészek listázása
    interface_combobox = ttk.Combobox(root, values=get_friendly_interfaces(), width=65)
    interface_combobox.pack(pady=5)
    interface_combobox.current(0)  # Alapértelmezett interfész kiválasztása

    # Görgethető keret létrehozása a táblázathoz
    canvas = tk.Canvas(root)
    canvas.pack(fill=tk.BOTH, expand=True)

    table_frame = tk.Frame(canvas)  # table_frame globális változó létrehozása
    canvas.create_window((0, 0), window=table_frame, anchor='nw')

    # Eszközök beolvasásának gombja
    scan_button = tk.Button(root, text="Eszközök beolvasása", command=scan_devices)
    scan_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()