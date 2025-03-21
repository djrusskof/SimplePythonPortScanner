import time
import tkinter as tk
from PIL import Image, ImageTk
from tkinter import ttk
import ctypes
import socket

''' 
Constants
'''
START_SCAN = "Start"
STOP_SCAN = "Stop"

'''
Function to Check if a port on a remote host is open.
'''
def is_port_open(host, port):
    """
    Check if a port on a remote host is open.
    
    :param host: Hostname ou IP address (ex. '127.0.0.1' ou 'example.com')
    :param port: Port number to check (ex. 80)
    :return: True if the port is open, False otherwise
    """
    opened = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 1s timeout
    s.settimeout(0.2)
    opened = s.connect_ex((host, port)) == 0
    s.close()
    return opened


'''
Function to start the port scan on the host.
'''
def start_scan():

    displayEndScanTime = False
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
        buttonStartScan.config(text=START_SCAN)
    else:
        buttonStartScan.config(text=STOP_SCAN)
        # Clear previous scan results
        textArea.delete(1.0, tk.END)
        # Display time of start scan
        textArea.insert(tk.END, f"Scan started at {time.strftime('%H:%M:%S')}\n", "timestamp")

    # Scan every port in the range
    for i in range(startPort, endPort + 1):
        if buttonStartScan.cget("text") == STOP_SCAN:
           
            if is_port_open(host, i):
                textArea.insert(tk.END, f"Port {i} on host {host} is opened.\n", "opened")
                print(f"Port {i} on host {host} is opened.")
            else:
                textArea.insert(tk.END, f"Port {i} on host {host} is closed.\n", "closed")
                print(f"Port {i} on host {host} is closed.")
            textArea.see("end")
            root.update()
        else:
            break
    else:
        displayEndScanTime=True

    # Display time of end scan
    if displayEndScanTime:
        textArea.insert(tk.END, f"Scan ended at {time.strftime('%H:%M:%S')}\n", "timestamp")

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
#root.resizable(False, False)
root.geometry("800x600")
root.minsize(800, 600)

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

top.grid_columnconfigure(0, weight=1, uniform="ZOB")
top.grid_columnconfigure(1, weight=1, uniform="ZOB")
top.grid_columnconfigure(2, weight=1, uniform="ZOB")
top.grid_columnconfigure(3, weight=1, uniform="ZOB")
top.grid_columnconfigure(4, weight=1, uniform="ZOB")


# Desired image size
appImageSize = (50, 50)

imgApp = load_and_resize_image("images/SPPS.png", appImageSize)

selectedScanType = tk.StringVar()

# Create the label to display app image
labelAppImage = tk.Label(top, image=imgApp)
labelAppImage.grid(row=0, column=0, columnspan=5)

# Create the label to indicates the user to type a hosntame / ip address
labelTypeHost = tk.Label(top, text="Please type hostname or IP address and port or port range :", pady=5)
labelTypeHost.grid(row=1, column=0, columnspan=5)

# Create the entry to type the hostname / ip address
entryHost = tk.Entry(top, width=50, justify="center")
entryHost.grid(row=2, column=0, columnspan=2, padx=5)

# Create the entry to type the port / port range
entryPort = tk.Entry(top, width=20, justify="center")
entryPort.grid(row=2, column=2, padx=5)

# Create the combobox to select the scan type
scanType = ttk.Combobox(top, values=["TCP", "UDP"], textvariable=selectedScanType, state="readonly", width=5)
scanType.set("TCP")
scanType.grid(row=2, column=3, padx=5)

# Create the button to start the scan
buttonStartScan = tk.Button(top, text=START_SCAN, command=start_scan)
buttonStartScan.grid(row=2, column=4)



# Create the label to display app image
#labelAppImage = tk.Label(root, image=imgApp, width=50, height=50)
#labelAppImage.pack(in_=top)

# Create the label to indicates the user to type a hosntame / ip address
# labelTypeHost = tk.Label(root, text="Please type hostname or IP address and port or port range :", pady=10)
# labelTypeHost.pack(in_=top)

# Create the entry to type the hostname / ip address
# entryHost = tk.Entry(root, width=30)
# entryHost.pack(in_=top, side=tk.LEFT) 

# # Create the entry to type the port / port range
# entryPort = tk.Entry(root, width=10)
# entryPort.pack(in_=top, side=tk.LEFT)

# # Create the button to start the scan
# buttonStartScan = tk.Button(root, text=START_SCAN, command=start_scan, width=10)
# buttonStartScan.pack(in_=top, side=tk.RIGHT)

# Create the text area to display the scan results
textArea = tk.Text(root)
textArea.pack(in_=bottom, padx=5, pady=5, fill=tk.BOTH, expand=True)

# Define tags for coloring text
textArea.tag_configure("opened", foreground="green")
textArea.tag_configure("closed", foreground="red")
textArea.tag_configure("timestamp", foreground="gray")

root.mainloop()