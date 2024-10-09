from scapy.all import ARP, Ether, srp, get_if_list, get_if_addr
import paramiko
import tkinter as tk
from tkinter import ttk
import psutil
import ipaddress
import socket

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

def ssh_interactive_shell(ip):
    """Interaktív SSH kapcsolat létrehozása az eszközhöz.""" 
    username = "administrator"
    password = "Labor123-"

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password)

        shell = client.invoke_shell()
        return shell, client
    except Exception as e:
        return None, f"Hiba az SSH kapcsolat során: {e}"

def send_command(shell, command):
    """Parancs elküldése az interaktív SSH session-ön keresztül.""" 
    try:
        shell.send(command + "\n")
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

def open_device_panel(ip):
    """Új ablak megnyitása és gombok hozzáadása az interaktív SSH session-höz.""" 
    panel = tk.Toplevel(root)
    panel.title(f"Eszköz kezelése - {ip}")

    shell, error_or_client = ssh_interactive_shell(ip)

    if not shell:
        output_label = tk.Label(panel, text=error_or_client)
        output_label.pack(pady=10)
        return

    # Szám mező és állapot kiválasztása
    input_frame = tk.Frame(panel)
    input_frame.pack(pady=10)

    # Szám mező (kicsi méret)
    number_entry = tk.Entry(input_frame, width=10)  # Kisebb szélesség
    number_entry.pack(side=tk.LEFT, padx=5)

    # Állapot kiválasztása (kicsi méret)
    status_var = tk.StringVar(value="fel")  # Alapértelmezett állapot "fel"
    status_combobox = ttk.Combobox(input_frame, textvariable=status_var, values=["fel", "le"], width=5)  # Kisebb szélesség
    status_combobox.pack(side=tk.LEFT, padx=5)

    def toggle_port_status():
        number = number_entry.get()
        status = status_var.get()
        output = send_command(shell, "")
        command = ""

        if output[0] != "[": 
            command += "system-view\n"
        if status == "fel":
            command += f"interface GE1/0/{number}\nundo shutdown\n"
        elif status == "le":
            command += f"interface GE1/0/{number}\nshutdown\n"

        output = send_command(shell, command)
        output_label.config(text=output)

    # Gomb a port állapotának változtatására (közepes méret)
    status_button = tk.Button(panel, text="Állapot változtatása", command=toggle_port_status, width=15)  # Közepes szélesség
    status_button.pack(pady=10)

    output_label = tk.Label(panel, text="", anchor="w", justify="left", relief="sunken", wraplength=500)
    output_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def on_close():
        error_or_client.close()  # SSH kapcsolat lezárása
        panel.destroy()

    panel.protocol("WM_DELETE_WINDOW", on_close)

def create_table(devices):
    """Táblázat létrehozása az eszközökkel.""" 
    global table_frame  # Jelentsd ki globálisként
    for widget in table_frame.winfo_children():
        widget.destroy()

    tk.Label(table_frame, text="IP cím", font=('bold', 12)).grid(row=0, column=0, padx=10, pady=10)
    tk.Label(table_frame, text="Belépés", font=('bold', 12)).grid(row=0, column=1, padx=10, pady=10)

    for index, device in enumerate(devices, start=1):
        tk.Label(table_frame, text=device['ip']).grid(row=index, column=0, padx=10, pady=5)
        login_button = tk.Button(table_frame, text="Belépés", command=lambda ip=device['ip']: open_device_panel(ip))
        login_button.grid(row=index, column=1, padx=10, pady=5)

    table_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))

def netmask_to_cidr(netmask):
    """A netmask átalakítása CIDR formátumba.""" 
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))

def calculate_subnet(ip, netmask):
    """Alhálózat számítása IP-cím és netmask alapján.""" 
    # IP hálózat kiszámítása
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    cidr = netmask_to_cidr(netmask)  # CIDR számítása
    return f"{network.network_address}/{cidr}"

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

    print(subnet)
    return subnet  # Visszaadja az alhálózatot CIDR formátumban

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