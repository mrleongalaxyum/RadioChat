# === APRS GUI Chat aplikacija putem DireWolf KISS TCP ===
# Opis: Ova aplikacija omogućuje slanje i primanje APRS poruka preko DireWolf-a
# koristeći KISS protokol putem TCP konekcije. Prikazuje poruke u GUI sučelju,
# validira korisnički unos, koristi AX.25 enkodiranje i lokalno sprema poruke u SQLite bazu.

import socket
import threading
import sqlite3
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext, messagebox
import re

# === BAZA PODATAKA ===
# Naziv datoteke SQLite baze koja se koristi za pohranu poruka
DB_NAME = "messages.db"
DEFAULT_CALLSIGN="9AXYZ-1"
def init_db():
    """
    Inicijalizira bazu podataka.
    Ako tablica 'messages' ne postoji, kreira se.
    Svaka poruka ima:
    - ID (automatski)
    - timestamp (vrijeme slanja/prijema)
    - direction ('TX' ili 'RX')
    - address (source ili destinacija)
    - message (tekst poruke)
    """
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            direction TEXT NOT NULL,
            address TEXT NOT NULL,
            message TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_message(timestamp, direction, address, message):
    """
    Spremi jednu poruku u bazu.
    Argumenti:
    - timestamp: vrijeme poruke u formatu YYYY-MM-DD HH:MM:SS
    - direction: 'TX' (poslana) ili 'RX' (primljena)
    - address: izvorna ili ciljana AX.25 adresa
    - message: tekst poruke
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            INSERT INTO messages (timestamp, direction, address, message)
            VALUES (?, ?, ?, ?)
        ''', (timestamp, direction, address, message))
        conn.commit()
        conn.close()
        print(f"[DB] Spremljeno u bazu: {timestamp}, {direction}, {address}, {message}")
    except Exception as e:
        print(f"[DB ERROR] {e}")


# === DIREWOLF TCP KISS konfiguracija ===
# Ovo su lokalni parametri za spajanje na DireWolf preko KISS TCP-a.
KISS_RX_PORT = 8001  # Port na kojem DireWolf šalje dolazne frameove
KISS_TX_PORT = 8001  # Port na koji se šalju odlazni frameovi
KISS_HOST = "127.0.0.1"  # DireWolf najčešće radi lokalno


def kiss_unwrap(data):
    """
    Parsira sirovi KISS okvir i vraća samo payload.

    Pretpostavlja da su početak i kraj framea označeni s 0xC0 (FEND).
    KISS frame izgleda ovako: 0xC0 + cmd + payload + 0xC0

    :param data: Primljeni bajtovi s TCP-a
    :return: Bajtovi bez FEND okvira
    """
    if data.startswith(b'\xC0') and data.endswith(b'\xC0'):
        return data[1:-1]
    return data  # ako nije ispravno upakiran, vrati nepromijenjeno


def kiss_wrap(data):
    """
    Omotava AX.25 payload u KISS okvir za slanje preko TCP-a.

    Format:
    - FEND (0xC0)
    - Command (0x00 za obični podatkovni frame)
    - Payload
    - FEND (0xC0)

    :param data: AX.25 frame
    :return: KISS frame
    """
    return b'\xC0\x00' + data + b'\xC0'


def parse_ax25_addresses(payload: bytes):
    """
    Ekstrahira pozivni znak izvora i odredišta iz AX.25 frame headera.

    AX.25 adrese kodirane su u prvih 14 bajtova framea (2x 7B):
    - svaki ASCII znak pomaknut je ulijevo (<<1)
    - zadnji bajt sadrži SSID i end-flag

    :param payload: AX.25 frame (bajtovi)
    :return: (source_callsign, destination_callsign)
    """

    def decode_callsign(addr: bytes):
        # Dekodira jedan 7-bajtni AX.25 address field
        callsign = ''.join([chr(b >> 1) for b in addr[:6]]).strip()
        ssid = (addr[6] >> 1) & 0x0F  # SSID je u zadnjem bajtu, bitovi 1–4
        if ssid > 0:
            return f"{callsign}-{ssid}"
        return callsign

    if len(payload) < 14:
        return "UNKNOWN", "UNKNOWN"

    dest_addr = payload[0:7]
    src_addr = payload[7:14]

    dest = decode_callsign(dest_addr)
    src = decode_callsign(src_addr)

    return src, dest


def encode_ax25_frame(src, dest, message):
    """
    Sastavlja AX.25 UI-frame s podatkovnim poljem.

    Format:
    - 7 bajtova: adresa odredišta
    - 7 bajtova: adresa izvora
    - 7 bajtova: WIDE1-1
    - 7 bajtova: WIDE2-1 (zadnja s postavljenim end-flagom)
    - 1 bajt: kontrolni (0x03 = UI-frame)
    - 1 bajt: PID (0xF0 = no Layer 3)
    - payload

    :param src: string poput "9A1XYZ-1"
    :param dest: string poput "PYTHON"
    :param message: korisnička poruka (string)
    :return: AX.25 frame kao bajtovi
    """

    def ax25_address(callsign, ssid, last=False):
        # Enkodira jedan AX.25 address field (7 bajtova)
        callsign = callsign.ljust(6)  # popuni s razmacima ako kraći
        addr = bytes([(ord(c) << 1) for c in callsign])
        ssid_byte = 0b01100000 | ((int(ssid) & 0x0F) << 1)  # bitovi 7 i 6 postavljeni, SSID u bitovima 1–4
        if last:
            ssid_byte |= 1  # postavi end-flag (bit 0)
        return addr + bytes([ssid_byte])

    # Parsiranje callsign i SSID (zadani SSID ako nije specificiran)
    src_name, src_ssid = (src.split('-') + ['0'])[:2]
    dest_name, dest_ssid = (dest.split('-') + ['0'])[:2]

    frame = b''
    frame += ax25_address(dest_name, dest_ssid)
    frame += ax25_address(src_name, src_ssid)
    frame += ax25_address('WIDE1', 1)
    frame += ax25_address('WIDE2', 1, last=True)
    frame += b'\x03'  # control byte (UI frame)
    frame += b'\xf0'  # PID (no layer 3 protocol)
    frame += message.encode()  # korisnički payload

    return frame


def is_valid_callsign(callsign):
    """
    Provjerava je li pozivni znak valjan prema AX.25/APRS pravilima.

    - 1 do 6 alfanumeričkih znakova (A–Z, 0–9)
    - Opcionalno: sufiks "-0" do "-15"

    :param callsign: string, npr. "9A1XYZ-2"
    :return: True ako valjan, False inače
    """
    match = re.fullmatch(r'[A-Z0-9]{1,6}(-[0-9]{1,2})?', callsign)
    if not match:
        return False
    if '-' in callsign:
        ssid = int(callsign.split('-')[1])
        return 0 <= ssid <= 15
    return True


# === GUI + Logika aplikacije za slanje i primanje APRS poruka preko KISS TCP ===
class ChatApp:
    def __init__(self, root):
        # Inicijalizacija glavnog GUI prozora
        self.root = root
        self.root.title("RadioChat")
        self.root.resizable(True, True)

        # === Gornji red GUI-a: unos pozivnog znaka i postavki ===
        top_frame = tk.Frame(root)
        top_frame.grid(row=0, column=0, columnspan=2, sticky="we", padx=10, pady=(10, 0))

        # Labela i unos za pozivni znak
        self.callsign_label = tk.Label(top_frame, text="Tvoj pozivni znak:")
        self.callsign_label.pack(side='left')

        self.callsign_entry = tk.Entry(top_frame, width=15)
        self.callsign_entry.insert(0, DEFAULT_CALLSIGN)  # početna vrijednost

        # === Validacija unosa pozivnog znaka ===
        def validate_callsign(P):
            import re
            if len(P) > 9:
                return False
            if P == "":
                return True  # dopušta brisanje svega
            if '-' in P:
                parts = P.split('-')
                if len(parts) != 2:
                    return False
                callsign, ssid = parts
                if not re.fullmatch(r'[A-Z0-9]{0,6}', callsign):
                    return False
                if not re.fullmatch(r'[0-9]{0,2}', ssid):
                    return False
                if ssid != "":
                    if not 0 <= int(ssid) <= 15:
                        return False
                return True
            else:
                return bool(re.fullmatch(r'[A-Z0-9]{0,6}', P))

        self.current_callsign = self.callsign_entry.get().strip().upper()
        self.callsign_entry.pack(side='left', padx=(5, 0))

        # Povezivanje validacije s Entry widgetom
        vcmd_call = (self.root.register(validate_callsign), '%P')
        self.callsign_entry.config(validate='key', validatecommand=vcmd_call)

        # === Unos destinacije (adresata poruka) ===
        self.dest_label = tk.Label(top_frame, text="Adresa za primanje:")
        self.dest_label.pack(side='left', padx=(20, 0))

        self.dest_entry = tk.Entry(top_frame, width=15)
        self.dest_entry.insert(0, "PYTHON")
        self.dest_entry.pack(side='left', padx=(5, 0))

        # Validacija: destinacija max 9 znakova (APRS ograničenje)
        def validate_dest(P):
            return len(P) <= 9
        vcmd = (self.root.register(validate_dest), '%P')
        self.dest_entry.config(validate='key', validatecommand=vcmd)

        # Gumb za primjenu novih postavki pozivnog znaka i adrese
        self.apply_button = tk.Button(top_frame, text="Primijeni", command=self.apply_settings)
        self.apply_button.pack(side='left', padx=(20, 0))

        # Checkbox za prikaz vlastitih poruka
        self.show_own_var = tk.BooleanVar(value=False)
        self.show_own_checkbox = tk.Checkbutton(
            top_frame, text="Prikaži vlastite RX poruke", variable=self.show_own_var)
        self.show_own_checkbox.pack(side='left', padx=(20, 0))

        # === Polje za prikaz poruka ===
        self.chat_area = scrolledtext.ScrolledText(root, state='disabled', width=60, height=20)
        self.chat_area.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        # === Polje za unos nove poruke ===
        self.input_entry = tk.Entry(root)
        self.input_entry.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        self.input_entry.bind("<Return>", lambda event: self.send_message())  # Enter = Pošalji

        self.send_button = tk.Button(root, text="Pošalji", command=self.send_message)
        self.send_button.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        # === Skaliranje GUI layouta ===
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=0)

        # === TCP konekcije na DireWolf KISS portove ===
        self.sock_tx = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_tx.connect((KISS_HOST, KISS_TX_PORT))

        self.sock_rx = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_rx.connect((KISS_HOST, KISS_RX_PORT))

        # Startanje thread-a za primanje poruka
        threading.Thread(target=self.receive_loop, daemon=True).start()
        print("GUI inicijaliziran.")
        self.display_message("INFO", "SYSTEM", "GUI je pokrenut.")

    def apply_settings(self):
        """Aktivira nove vrijednosti pozivnog znaka i adrese za primanje."""
        self.current_callsign = self.callsign_entry.get().strip().upper()
        dest = self.dest_entry.get().strip().upper()
        print(f"[POSTAVKE] Postavljen pozivni znak: {self.current_callsign}, destinacija: {dest}")
        self.display_message("INFO", "SYSTEM",
                             f"Postavke ažurirane: Callsign={self.current_callsign}, Destinacija={dest}")

    def display_message(self, direction, address, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.chat_area.configure(state='normal')

        # (Re)definiraj stilove boja svaki put
        self.chat_area.tag_config("rx", foreground="green")
        self.chat_area.tag_config("tx", foreground="blue")
        self.chat_area.tag_config("info", foreground="black")

        # Odaberi tag prema smjeru poruke
        tag = {
            "RX": "rx",
            "TX": "tx",
            "INFO": "info"
        }.get(direction, "")

        # Formatiraj liniju poruke
        line = f"[{timestamp}] {direction} {address}: {message}\n"

        # Ubaci s bojom
        self.chat_area.insert(tk.END, line, tag)
        self.chat_area.configure(state='disabled')
        self.chat_area.yview(tk.END)

        # Spremi u bazu
        save_message(timestamp, direction, address, message)

        # Terminal boje (ANSI escape)
        color = {
            "RX": "\033[92m",  # zeleno
            "TX": "\033[94m",  # plavo
            "INFO": "\033[30m"  # sivo
        }.get(direction, "")
        reset = "\033[0m"
        print(f"{color}[DISPLAY] {direction} {address}: {message}{reset}")

    def send_message(self):
        """Uzima poruku iz input polja, enkodira je u AX.25 format i šalje putem TCP veze."""
        message = self.input_entry.get().strip()
        if not message:
            return

        dest = self.dest_entry.get().strip().upper()
        source = self.current_callsign

        try:
            ax25_payload = encode_ax25_frame(source, dest, f":{dest.ljust(9)}:{message}")
            self.sock_tx.sendall(kiss_wrap(ax25_payload))
            self.display_message("TX", dest, message)
            print(f"[TX] AX.25 frame sent: {source}>{dest} : {message}")
        except Exception as e:
            messagebox.showerror("Greška", f"Ne mogu poslati poruku: {e}")

        self.input_entry.delete(0, tk.END)

    def receive_loop(self):
        """Neprekidno prima KISS frameove i prikazuje poruke adresirane na korisnika."""
        buffer = b""
        while True:
            try:
                data = self.sock_rx.recv(1024)
                if not data:
                    continue
                buffer += data
                while b'\xC0' in buffer:
                    start = buffer.find(b'\xC0')
                    end = buffer.find(b'\xC0', start + 1)
                    if end == -1:
                        break
                    frame = buffer[start + 1:end]
                    buffer = buffer[end + 1:]

                    if not frame:
                        continue  # ignoriraj prazan frame

                    kiss_cmd = frame[0]
                    payload = frame[1:]

                    print(f"[RX] Raw payload: {payload.hex()}")

                    try:
                        src, _ = parse_ax25_addresses(payload)
                        info_field = payload[14:]
                        text = info_field.decode(errors='ignore').strip()
                        print(f"[RX] Decoded info field: {text}")

                        # Parsiranje poruke u APRS formatu :DESTINATION:message
                        parts = text.split(':')
                        for i in range(len(parts) - 2):
                            dest = parts[i + 1].strip().upper()
                            msg = ':'.join(parts[i + 2:]).strip()

                            my_dest = self.dest_entry.get().strip().upper()
                            my_call = self.current_callsign

                            if dest == my_dest:
                                if src.upper() == my_call and not self.show_own_var.get():
                                    print(f"[RX FILTER] Ignoriram vlastitu poruku: {msg}")
                                    break

                                print(f"[RX PARSE] dest='{dest}', source='{src}', msg='{msg}'")
                                self.root.after(0, self.display_message, "RX", src, msg)
                                break
                        else:
                            print(f"[RX PARSE] Ignorirano – nema :DEST: format s {self.dest_entry.get()} u tekstu.")

                    except Exception as e:
                        print(f"[RX] Greška u obradi frame-a: {e}")
                        continue

            except Exception as e:
                print(f"[RX LOOP] Greška u primanju: {e}")
                break


# === GLAVNI DIO ===
if __name__ == "__main__":
    # Pokreće se samo ako se ovaj fajl izvršava direktno (a ne uvozi kao modul)

    init_db()  # inicijalizira SQLite bazu ako još ne postoji

    root = tk.Tk()  # kreira glavni Tkinter prozor
    app = ChatApp(root)  # instancira GUI aplikaciju
    root.mainloop()  # pokreće Tkinter event loop (glavna petlja aplikacije)
