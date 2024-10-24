import os
import re

def extract_mac_addresses_from_file(filepath):
    """Kivonja a MAC címeket a megadott fájlból, pontok nélkül."""
    mac_addresses = set()
    with open(filepath, 'r') as file:
        for line in file:
            # MAC címek keresése reguláris kifejezéssel
            matches = re.findall(r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})', line, re.IGNORECASE)
            for match in matches:
                # Pontok eltávolítása és kettőspontokkal helyettesítése
                cleaned_mac = match.replace('.', '')
                mac_addresses.add(cleaned_mac)  # Hozzáadás halmazhoz
    return mac_addresses

def load_mac_addresses_from_directory(directory):
    """Beolvassa az összes .txt fájlt a megadott mappából, és a MAC címeket IP címekhez rendeli."""
    ip_mac_dict = {}
    
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            # IP cím kinyerése a fájlnévből (hostname.txt -> hostname)
            full_name = str(filename[:-4])  # eltávolítjuk a .txt kiterjesztést
            ip_address_name =  full_name.split('-')[1] # itt használhatod a tényleges IP cím kinyerését, ha szükséges
            
            # MAC címek kinyerése
            mac_addresses = extract_mac_addresses_from_file(os.path.join(directory, filename))
            
            # Szótár frissítése
            if mac_addresses:
                ip_mac_dict[ip_address_name] = mac_addresses

    return ip_mac_dict

# Használat példa
mac_address_data = load_mac_addresses_from_directory("./")
for ip, macs in mac_address_data.items():
    print(f"IP: {ip}, MAC címek: {', '.join(macs)}")
