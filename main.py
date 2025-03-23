from PIL import Image, ImageTk
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.sctp import SCTP, SCTPChunkInit, SCTPChunkAbort
from scapy.sendrecv import sr, sr1
from tkinter import ttk

import ctypes
import time
import tkinter as tk


''' 
Constants
'''
START_SCAN = "Start"
STOP_SCAN = "Stop"

PORT_STATE_OPENED = "opened"
PORT_STATE_OPEN_FILTERED = "open|filtered"
PORT_STATE_FILTERED = "filtered"
PORT_STATE_UNFILTERED = "unfiltered"
PORT_STATE_CLOSED = "closed"

SCAN_TYPE_TCP = "TCP"
SCAN_TYPE_TCP_SYN = "TCP SYN"
SCAN_TYPE_UDP = "UDP"
SCAN_TYPE_SCTP = "SCTP"
SCAN_TYPE_NULL = "NULL"
SCAN_TYPE_FIN = "FIN"
SCAN_TYPE_XMAS = "xMas"
SCAN_TYPE_ACK = "ACK"
SCAN_TYPE_WINDOW = "Window"
SCAN_TYPE_MAIMON = "Maimon"


'''
Global variables
'''
openPortsList = []
openFilteredPortsList = []
unFilteredPortsList = []
filteredPortsList = []
closedPortsList = []


def tcp_connect_scan(host, port):
    """
    Check if a port on a remote host is open using TCP connect (complete 3-way handshake) scan with scapy.

    :param host: Hostname or IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :return: True if the port is open, False otherwise
    """

    portState = PORT_STATE_CLOSED
    # Create a SYN packet
    syn_packet = IP(dst=host)/TCP(dport=port, flags='S')
    # Send the packet and wait for a response
    response = sr1(syn_packet, timeout=1, verbose=False)

    if response is not None and response.haslayer(TCP):
        Packet = response.getlayer(TCP)
        if not Packet is None and Packet.flags == 0x12:  # SYN-ACK:
            # Send a ACK packet to terminate the 3-way handshake
            sr1(IP(dst=host)/TCP(dport=port, flags='A'), timeout=1, verbose=False)
            portState = PORT_STATE_OPENED

    return portState


def tcp_syn_scan(host, port, retries=3):
    """
    Realize a TCP SYN scan on a specific port of a host.

    :param host: Hostname or IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :param retries: Number of retries to send the SYN packet
    :return: True if the port is open, False otherwise
    """
    portState = PORT_STATE_FILTERED

    for i in range(retries):
        # Create a SYN packet
        syn_packet = IP(dst=host)/TCP(dport=port, flags='S')
        # Send the packet and wait for a response
        response = sr1(syn_packet, timeout=1, verbose=False)

        if response is not None:
            if response.haslayer(TCP):
                Packet = response.getlayer(TCP)
                if not Packet is None:
                    if Packet.flags == 0x12 or Packet.flags == 0x02:  # SYN-ACK or only SYN is admitted
                        # Send a RST packet to close connection without finalizing the 3-way handshake
                        sr(IP(dst=host)/TCP(dport=port, flags='R'),
                           timeout=1, verbose=False)
                        portState = PORT_STATE_OPENED
                        break
                    elif Packet.flags == 0x14 or Packet.flags == 0x04:  # SYN-RST or only RST
                        portState = PORT_STATE_CLOSED
                        break
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if not icmp_layer is None:
                    if icmp_layer.type == 3 and icmp_layer.code in [0, 1, 2, 3, 9, 10, 13]:
                        # ICMP Type 3, Code 0, 1, 2, 3, 9, 10, 13: Port is filtered
                        portState = PORT_STATE_FILTERED
                    break

    return portState


def udp_scan(host, port, retries=3):
    """
    Realize a UDP scan on a specific port of a host.

    :param host: Hostname or IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :param retries: Number of retries to send the UDP packet
    :return: True if the port is open or filtered, False if the port is closed
    """

    portState = PORT_STATE_OPEN_FILTERED

    for i in range(retries):
        # Create a UDP packet
        udp_packet = IP(dst=host)/UDP(dport=port)
        # Send the packet and wait for a response
        response = sr1(udp_packet, timeout=1, verbose=False)

        if response is not None and response.haslayer(ICMP):
            icmp_layer = response.getlayer(ICMP)
            if not icmp_layer is None:
                if icmp_layer.type == 3 and icmp_layer.code == 3:
                    # ICMP Port Unreachable message received, port is closed
                    portState = PORT_STATE_CLOSED
                    break
                elif icmp_layer.type == 3 and icmp_layer.code in [0, 1, 2, 9, 10, 13]:
                    # ICMP Type 3, Code 0, 1, 2, 9, 10, 13: Port is filtered
                    portState = PORT_STATE_FILTERED
                    break
    return portState


def sctp_scan(host, port, retries=3):
    """
    Realize a SCTP scan on a specific port of a host.

    :param host: Hostname or IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :param retries: Number of retries to send the SCTP packet
    :return: True if the port is open or filtered, False if the port is closed
    """

    portState = PORT_STATE_FILTERED

    for i in range(retries):
        # Create a SCTP packet
        sctp_packet = IP(dst=host)/SCTP(dport=port)/SCTPChunkInit()
        # Send the packet and wait for a response
        response = sr1(sctp_packet, timeout=1, verbose=False)

        if response is not None:
            if response.haslayer(SCTPChunkInit):
                portState = PORT_STATE_OPENED
                break
            elif response.haslayer(SCTPChunkAbort):
                portState = PORT_STATE_CLOSED
                break
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer is not None and icmp_layer.type == 3 and icmp_layer.code in [0, 1, 2, 3, 9, 10, 13]:
                    portState = PORT_STATE_FILTERED
                    break
    return portState


def tcp_null_scan(host, port, retries=3, verbose=False):
    """
    Realize a TCP NULL scan on a specific port of a host.

    :param host: Hostname or IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :param retries: Number of retries to send the TCP packet
    :param verbose: Boolean to control verbosity
    :return: Port state (opened, filtered, or closed)
    """
    portState = PORT_STATE_FILTERED

    for i in range(retries):
        # Create a TCP NULL packet (no flags set)
        null_packet = IP(dst=host)/TCP(dport=port, flags='')
        # Send the packet and wait for a response
        response = sr1(null_packet, timeout=1, verbose=verbose)

        if response is not None:
            if response.haslayer(TCP):
                Packet = response.getlayer(TCP)
                if not Packet is None and Packet.flags == 0x14:  # RST-ACK
                    portState = PORT_STATE_CLOSED
                    break
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer is not None and icmp_layer.type == 3 and icmp_layer.code in [0, 1, 2, 3, 9, 10, 13]:
                    portState = PORT_STATE_FILTERED
                    break
        else:
            portState = PORT_STATE_OPENED

    return portState


def tcp_fin_scan(host, port, retries=3, verbose=False):
    """
    Realize a TCP FIN scan on a specific port of a host.

    :param host: Hostname or IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :param retries: Number of retries to send the TCP packet
    :param verbose: Boolean to control verbosity
    :return: Port state (opened, filtered, or closed)
    """
    portState = PORT_STATE_FILTERED

    for i in range(retries):
        # Create a TCP FIN packet
        fin_packet = IP(dst=host)/TCP(dport=port, flags='F')
        # Send the packet and wait for a response
        response = sr1(fin_packet, timeout=1, verbose=verbose)

        if response is not None:
            if response.haslayer(TCP):
                Packet = response.getlayer(TCP)
                if not Packet is None and Packet.flags == 0x14:  # RST-ACK
                    portState = PORT_STATE_CLOSED
                    break
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer is not None and icmp_layer.type == 3 and icmp_layer.code in [0, 1, 2, 3, 9, 10, 13]:
                    portState = PORT_STATE_FILTERED
                    break
        else:
            portState = PORT_STATE_OPENED

    return portState


def tcp_xmas_scan(host, port, retries=3, verbose=False):
    """
    Realize a TCP Xmas scan on a specific port of a host.

    :param host: Hostname or IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :param retries: Number of retries to send the TCP packet
    :param verbose: Boolean to control verbosity
    :return: Port state (opened, filtered, or closed)
    """
    portState = PORT_STATE_FILTERED

    for i in range(retries):
        # Create a TCP Xmas packet (FIN, PSH, URG flags set)
        xmas_packet = IP(dst=host)/TCP(dport=port, flags='FPU')
        # Send the packet and wait for a response
        response = sr1(xmas_packet, timeout=1, verbose=verbose)

        if response is not None:
            if response.haslayer(TCP):
                Packet = response.getlayer(TCP)
                if not Packet is None and Packet.flags == 0x14:  # RST-ACK
                    portState = PORT_STATE_CLOSED
                    break
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer is not None and icmp_layer.type == 3 and icmp_layer.code in [0, 1, 2, 3, 9, 10, 13]:
                    portState = PORT_STATE_FILTERED
                    break
        else:
            portState = PORT_STATE_OPENED

    return portState


def tcp_ack_scan(host, port, retries=3):
    """
    Realize a TCP ACK scan on a specific port of a host.

    :param host: Hostname or IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :param retries: Number of retries to send the TCP packet
    :param verbose: Boolean to control verbosity
    :return: Port state (filtered or unfiltered)
    """
    portState = PORT_STATE_FILTERED

    for i in range(retries):
        # Create a TCP ACK packet
        ack_packet = IP(dst=host)/TCP(dport=port, flags='A')
        # Send the packet and wait for a response
        response = sr1(ack_packet, timeout=1, verbose=False)

        if response is not None:
            if response.haslayer(TCP):
                Packet = response.getlayer(TCP)
                if not Packet is None and Packet.flags == 0x04:  # RST
                    portState = PORT_STATE_UNFILTERED
                break
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer is not None and icmp_layer.type == 3 and icmp_layer.code in [0, 1, 2, 3, 9, 10, 13]:
                    portState = PORT_STATE_FILTERED
                    break

    return portState


def tcp_window_scan(host, port, retries=3):
    """
    Realize a TCP Window scan on a specific port of a host.

    :param host: Hostname or IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :param retries: Number of retries to send the TCP packet
    :param verbose: Boolean to control verbosity
    :return: Port state (opened or closed)
    """
    portState = PORT_STATE_FILTERED

    for i in range(retries):
        # Create a TCP ACK packet
        ack_packet = IP(dst=host)/TCP(dport=port, flags='A')
        # Send the packet and wait for a response
        response = sr1(ack_packet, timeout=1, verbose=False)

        if response is not None:
            if response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer is not None and tcp_layer.flags == 0x04:  # RST
                    if tcp_layer.window > 0:
                        portState = PORT_STATE_OPENED
                    else:
                        portState = PORT_STATE_CLOSED
                    break
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer is not None and icmp_layer.type == 3 and icmp_layer.code in [0, 1, 2, 3, 9, 10, 13]:
                    portState = PORT_STATE_FILTERED
                    break

    return portState


def tcp_maimon_scan(host, port, retries=3):
    """
    Realize a TCP Maimon scan on a specific port of a host.

    :param host: Hostname or IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :param retries: Number of retries to send the TCP packet
    :param verbose: Boolean to control verbosity
    :return: Port state (opened, filtered, or closed)
    """
    portState = PORT_STATE_FILTERED

    for i in range(retries):
        # Create a TCP Maimon packet (FIN and ACK flags set)
        maimon_packet = IP(dst=host)/TCP(dport=port, flags='FA')
        # Send the packet and wait for a response
        response = sr1(maimon_packet, timeout=1, verbose=False)

        if response is not None:
            if response.haslayer(TCP):
                Packet = response.getlayer(TCP)
                if not Packet is None and Packet.flags == 0x14:  # RST-ACK
                    portState = PORT_STATE_CLOSED
                break
            elif response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer is not None and icmp_layer.type == 3 and icmp_layer.code in [0, 1, 2, 3, 9, 10, 13]:
                    portState = PORT_STATE_FILTERED
                    break
        else:
            portState = PORT_STATE_OPENED

    return portState


'''
Function to start the port scan on the host.
'''


def start_scan():

    displayEndScanTime = False
    endScanReason = "ended"
    # Extract port range to scan
    if "-" in entryPort.get():
        startPort, endPort = entryPort.get().split("-")
        startPort = int(startPort)
        endPort = int(endPort)
    elif entryPort.get() == "*":
        startPort = 1
        endPort = 65535
    else:
        startPort = int(entryPort.get())
        endPort = startPort

    # Get host/ip to scan
    host = entryHost.get()

    if buttonStartScan.cget("text") == STOP_SCAN:
        displayEndScanTime = True
        endScanReason = "canceled"
        buttonStartScan.config(text=START_SCAN)
    else:
        openPortsList.clear()
        openFilteredPortsList.clear()
        unFilteredPortsList.clear()
        filteredPortsList.clear()
        closedPortsList.clear()

        buttonStartScan.config(text=STOP_SCAN)
        # Clear previous scan results
        textArea.delete(1.0, tk.END)
        # Display time of start scan
        textArea.insert(
            tk.END, f"Started {selectedScanType.get()} scan at {time.strftime('%H:%M:%S')}\n", "timestamp")

    # Scan every port in the range
    for i in range(startPort, endPort + 1):
        if buttonStartScan.cget("text") == STOP_SCAN:
            # Display the scan result line
            if (verbose_var.get() == True):
                textArea.insert(
                    tk.END, f"{time.strftime('%H:%M:%S')} ", "timestamp")
                textArea.insert(tk.END, f"Port ")
                textArea.insert(tk.END, f"{i} ", "port")
                textArea.insert(tk.END, f"on host ")
                textArea.insert(tk.END, f"{host} ", "host")
                textArea.insert(tk.END, f"is ")

            # Following scan type selected, call the appropriate function
            if selectedScanType.get() == SCAN_TYPE_TCP:
                portState = tcp_connect_scan(host, i)
            elif selectedScanType.get() == SCAN_TYPE_TCP_SYN:
                portState = tcp_syn_scan(host, i)
            elif selectedScanType.get() == SCAN_TYPE_UDP:
                portState = udp_scan(host, i)
            elif selectedScanType.get() == SCAN_TYPE_SCTP:
                portState = sctp_scan(host, i)
            elif selectedScanType.get() == SCAN_TYPE_NULL:
                portState = tcp_null_scan(host, i)
            elif selectedScanType.get() == SCAN_TYPE_FIN:
                portState = tcp_fin_scan(host, i)
            elif selectedScanType.get() == SCAN_TYPE_XMAS:
                portState = tcp_xmas_scan(host, i)
            elif selectedScanType.get() == SCAN_TYPE_ACK:
                portState = tcp_ack_scan(host, i)
            elif selectedScanType.get() == SCAN_TYPE_WINDOW:
                portState = tcp_window_scan(host, i)
            elif selectedScanType.get() == SCAN_TYPE_MAIMON:
                portState = tcp_maimon_scan(host, i)

            # Add the port to the appropriate list
            if (portState == PORT_STATE_OPENED):
                openPortsList.append(i)
            elif (portState == PORT_STATE_OPEN_FILTERED):
                openFilteredPortsList.append(i)
            elif (portState == PORT_STATE_UNFILTERED):
                unFilteredPortsList.append(i)
            elif (portState == PORT_STATE_FILTERED):
                filteredPortsList.append(i)
            elif (portState == PORT_STATE_CLOSED):
                closedPortsList.append(i)

            # Display the port state
            print(f"Port {i} on host {host} is {portState}.")
            if (verbose_var.get() == True):
                textArea.insert(tk.END, f"{portState}\n", f"{portState}")
                textArea.see("end")

            root.update()
        else:
            break
    else:
        displayEndScanTime = True

    # Display time of end scan
    if displayEndScanTime:
        textArea.insert(tk.END, f"{len(openPortsList)} opened port(s) : {openPortsList}, " +
                        f"{len(openFilteredPortsList)} opened|filtered port(s) : {openFilteredPortsList}, " +
                        f"{len(unFilteredPortsList)} unfiltered port(s) : {unFilteredPortsList}, " +
                        f"{len(filteredPortsList)} filtered port(s) : {filteredPortsList}, " +
                        f"{len(closedPortsList)} closed port(s) : {closedPortsList}\n", "timestamp")
        textArea.insert(
            tk.END, f"{selectedScanType.get()} scan {endScanReason} at {time.strftime('%H:%M:%S')}\n", "timestamp")
        textArea.see("end")

    buttonStartScan.config(text=START_SCAN)


'''
Function to load and resize an image
This function loads an image from a file and resizes it to the desired size.
It returns the image as a PhotoImage object.
'''


def load_and_resize_image(path, size):
    image = Image.open(path)
    image = image.resize(size)
    return ImageTk.PhotoImage(image)


# Create the main window
root = tk.Tk()
root.iconbitmap("images/SPPS.ico")
root.title("SPPS - Simple Python Port Scanner")

# Desired window size
window_width = 800
window_height = 600

root.minsize(window_width, window_height)

# Get the screen width and height
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate the position to center the window
position_x = (screen_width // 2) - (window_width // 2)
position_y = (screen_height // 2) - (window_height // 2)

# Set the geometry of the window
root.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")

myappid = u'djrusskof.simplepythonportscanner.1.0.0'
ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

# Create the top and bottom frames
top = tk.Frame(root)
bottom = tk.Frame(root)
top.pack(side=tk.TOP)
bottom.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

top.grid_rowconfigure(0, weight=1)
top.grid_rowconfigure(1, weight=1)
top.grid_rowconfigure(2, weight=1)

top.grid_columnconfigure(0, weight=1, uniform="uniform")
top.grid_columnconfigure(1, weight=1, uniform="uniform")
top.grid_columnconfigure(2, weight=1, uniform="uniform")
top.grid_columnconfigure(3, weight=1, uniform="uniform")
top.grid_columnconfigure(4, weight=1, uniform="uniform")


# Desired image size
appImageSize = (50, 50)

imgApp = load_and_resize_image("images/SPPS.png", appImageSize)

# Create a StringVar to store the selected scan type
selectedScanType = tk.StringVar()
# Create a BooleanVar to store the state of the verbose checkbox
verbose_var = tk.BooleanVar()

# Create the label to display app image
labelAppImage = tk.Label(top, image=imgApp)
labelAppImage.grid(row=0, column=0, columnspan=6)

# Create the label to indicates the user to type a hosntame / ip address
labelTypeHost = tk.Label(
    top, text="Please type hostname or IP address and port or port range :", pady=5)
labelTypeHost.grid(row=1, column=0, columnspan=6)

# Create the entry to type the hostname / ip address
entryHost = tk.Entry(top, width=50, justify="center")
entryHost.grid(row=2, column=0, columnspan=2, padx=5)

# Create the entry to type the port / port range
entryPort = tk.Entry(top, width=20, justify="center")
entryPort.grid(row=2, column=2, padx=5)

# Create the combobox to select the scan type
scanType = ttk.Combobox(top, values=[SCAN_TYPE_TCP, SCAN_TYPE_TCP_SYN, SCAN_TYPE_UDP, SCAN_TYPE_SCTP,
                                     SCAN_TYPE_NULL, SCAN_TYPE_FIN, SCAN_TYPE_XMAS, SCAN_TYPE_ACK,
                                     SCAN_TYPE_WINDOW, SCAN_TYPE_MAIMON], textvariable=selectedScanType, state="readonly", width=10)
scanType.set(SCAN_TYPE_TCP)
scanType.grid(row=2, column=3, padx=5)

# Create the verbose checkbox
verbose_checkbox = tk.Checkbutton(top, text="verbose", variable=verbose_var)
verbose_checkbox.grid(row=2, column=4, padx=5)

# Create the button to start the scan
buttonStartScan = tk.Button(top, text=START_SCAN, command=start_scan)
buttonStartScan.grid(row=2, column=5)

# Create the text area to display the scan results
textArea = tk.Text(root)
textArea.pack(in_=bottom, padx=5, pady=5, fill=tk.BOTH, expand=True)

# Define tags for coloring text
textArea.tag_configure(PORT_STATE_OPENED, foreground="green")
textArea.tag_configure(PORT_STATE_UNFILTERED, foreground="green")
textArea.tag_configure(PORT_STATE_CLOSED, foreground="red")
textArea.tag_configure(PORT_STATE_FILTERED, foreground="orange")
textArea.tag_configure(PORT_STATE_OPEN_FILTERED, foreground="orange")
textArea.tag_configure("timestamp", foreground="gray")
textArea.tag_configure("host", foreground="purple")
textArea.tag_configure("port", foreground="brown")

root.mainloop()
