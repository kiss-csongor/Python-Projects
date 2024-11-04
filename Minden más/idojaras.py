import requests
import tkinter as tk
from tkinter import messagebox

def get_weather(city):
    api_key = "f5428f122bf24790872193720241009"  # Cseréld ki a saját API kulcsodra
    base_url = f"http://api.weatherapi.com/v1/current.json?key={api_key}&q={city}&aqi=no"
    response = requests.get(base_url)
    return response.json()

város = "Budapest"
időjárás_adatok = get_weather(város)

def display_gui_weather(weather_data):
    if 'error' in weather_data:
        messagebox.showerror("Hiba", weather_data['error']['message'])
    else:
        location = weather_data['location']['name']
        temp_c = weather_data['current']['temp_c']
        condition = weather_data['current']['condition']['text']
        
        window = tk.Tk()
        window.title("Időjárás App")
        label = tk.Label(window, text=f"Város: {location}\nHőmérséklet: {temp_c} °C\nÁllapot: {condition}", font=('Helvetica', 14))
        label.pack(pady=20)
        window.mainloop()

display_gui_weather(időjárás_adatok)
