#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import scapy.all as scapy
import requests
from typing import List, Dict, Optional
import queue
import webbrowser

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.scanning = False
        self.scan_thread = None
        self.message_queue = queue.Queue()
        
        # Create GUI elements
        self.create_widgets()
        self.setup_styles()
        self.create_menu()
        
        # Start message processing
        self.process_messages()
    
    def setup_styles(self):
        """Setup modern styling"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Success.TLabel', foreground='green')
        style.configure('Error.TLabel', foreground='red')
        style.configure('Info.TLabel', foreground='blue')
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Network Scanner", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Network range frame
        range_frame = ttk.LabelFrame(main_frame, text="Scan Settings", padding="10")
        range_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        range_frame.columnconfigure(1, weight=1)
        
        # IP Range
        ttk.Label(range_frame, text="IP Range:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.ip_range_var = tk.StringVar(value="192.168.1.1/24")
        self.ip_range_entry = ttk.Entry(range_frame, textvariable=self.ip_range_var, width=20)
        self.ip_range_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Timeout
        ttk.Label(range_frame, text="Timeout (s):").grid(row=0, column=2, sticky=tk.W, padx=(10, 5))
        self.timeout_var = tk.StringVar(value="1")
        self.timeout_entry = ttk.Entry(range_frame, textvariable=self.timeout_var, width=5)
        self.timeout_entry.grid(row=0, column=3, sticky=tk.W)
        
        # Control buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(0, 10))
        
        # Scan button
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Stop button
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear button
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Help button
        self.help_button = ttk.Button(button_frame, text="Help", command=self.show_help)
        self.help_button.pack(side=tk.LEFT)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="5")
        status_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)
        
        self.status_label = ttk.Label(status_frame, text="Ready to scan", style='Info.TLabel')
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        # Progress bar
        self.progress_var = tk.StringVar()
        self.progress_bar = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="5")
        results_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Create Treeview for results
        columns = ('IP Address', 'MAC Address', 'Vendor')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.tree.heading('IP Address', text='IP Address')
        self.tree.heading('MAC Address', text='MAC Address')
        self.tree.heading('Vendor', text='Vendor')
        
        self.tree.column('IP Address', width=150, minwidth=150)
        self.tree.column('MAC Address', width=180, minwidth=180)
        self.tree.column('Vendor', width=300, minwidth=200)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Grid treeview and scrollbar
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Summary frame
        summary_frame = ttk.Frame(main_frame)
        summary_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.device_count_label = ttk.Label(summary_frame, text="Devices found: 0")
        self.device_count_label.pack(side=tk.LEFT)
        
        self.scan_time_label = ttk.Label(summary_frame, text="")
        self.scan_time_label.pack(side=tk.RIGHT)
        
        # Add tooltips
        self.create_tooltips()
    
    def get_vendor_info(self, mac_address: str) -> str:
        """Get vendor information for a MAC address with enhanced error handling"""
        try:
            # Validate MAC address format
            if not self.validate_mac_address(mac_address):
                return "Invalid MAC"
            
            # Clean MAC address
            mac_clean = mac_address.replace(':', '').replace('-', '').upper()
            if len(mac_clean) != 12:
                return "Invalid MAC"
            
            # Make API request
            url = f"https://api.macvendors.com/{mac_clean}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                vendor = response.text.strip()
                if vendor and len(vendor) > 0:
                    return vendor
                else:
                    return "Unknown"
            elif response.status_code == 404:
                return "Unknown"
            else:
                return f"API Error ({response.status_code})"
                
        except requests.exceptions.Timeout:
            return "Timeout"
        except requests.exceptions.ConnectionError:
            return "No Internet"
        except requests.exceptions.RequestException as e:
            return f"Request Error"
        except Exception as e:
            return "Error"
    
    def scan_network(self, ip_range: str, timeout: int):
        """Perform network scan in separate thread"""
        try:
            # Validate input parameters
            if not self.validate_ip_range(ip_range):
                self.message_queue.put(("error", f"Invalid IP range format: {ip_range}"))
                self.message_queue.put(("progress", False))
                return
            
            if timeout < 1 or timeout > 60:
                self.message_queue.put(("error", f"Invalid timeout value: {timeout} (must be 1-60 seconds)"))
                self.message_queue.put(("progress", False))
                return
            
            # Check network interface
            if not self.check_network_interface():
                self.message_queue.put(("error", "No network interface available"))
                self.message_queue.put(("progress", False))
                return
            
            # Check network connectivity
            if not self.check_network_connectivity():
                self.message_queue.put(("warning", "Network connectivity issues detected"))
            
            # Check privileges
            if not self.check_scanning_privileges():
                self.message_queue.put(("warning", "May need administrator privileges"))
            
            self.message_queue.put(("status", f"Scanning network: {ip_range}"))
            self.message_queue.put(("progress", True))
            
            # Create ARP request packet
            try:
                arp_request = scapy.ARP(pdst=ip_range)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
            except Exception as e:
                self.message_queue.put(("error", f"Failed to create ARP packet: {e}"))
                self.message_queue.put(("progress", False))
                return
            
            # Send packets and capture responses
            try:
                answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]
            except PermissionError:
                self.message_queue.put(("error", "Permission denied - try running as administrator"))
                self.message_queue.put(("progress", False))
                return
            except OSError as e:
                self.message_queue.put(("error", f"Network error: {e}"))
                self.message_queue.put(("progress", False))
                return
            except Exception as e:
                self.message_queue.put(("error", f"Scan failed: {e}"))
                self.message_queue.put(("progress", False))
                return
            
            # Process results
            device_count = 0
            for element in answered_list:
                if not self.scanning:  # Check if scan was stopped
                    break
                    
                try:
                    ip = element[1].psrc
                    mac = element[1].hwsrc
                    
                    # Validate MAC address
                    if not self.validate_mac_address(mac):
                        continue
                    
                    vendor = self.get_vendor_info(mac)
                    device_count += 1
                    
                    # Add to results
                    self.message_queue.put(("result", (ip, mac, vendor)))
                    
                except Exception as e:
                    self.message_queue.put(("warning", f"Error processing device: {e}"))
                    continue
            
            if device_count == 0:
                self.message_queue.put(("warning", "No devices found on the network"))
            
            self.message_queue.put(("status", f"Scan completed - Found {device_count} devices"))
            self.message_queue.put(("progress", False))
            
        except KeyboardInterrupt:
            self.message_queue.put(("status", "Scan interrupted by user"))
            self.message_queue.put(("progress", False))
        except Exception as e:
            self.message_queue.put(("error", f"Unexpected scan error: {e}"))
            self.message_queue.put(("progress", False))
    
    def start_scan(self):
        """Start network scan with comprehensive error handling"""
        if self.scanning:
            return
        
        try:
            # Get and validate input parameters
            ip_range = self.ip_range_var.get().strip()
            timeout_str = self.timeout_var.get().strip()
            
            # Validate IP range
            if not ip_range:
                messagebox.showerror("Input Error", "Please enter an IP range")
                return
            
            if not self.validate_ip_range(ip_range):
                messagebox.showerror("Input Error", 
                    f"Invalid IP range format: {ip_range}\n"
                    "Expected format: X.X.X.X/Y (e.g., 192.168.1.1/24)")
                return
            
            # Validate timeout
            try:
                timeout = int(timeout_str)
                if timeout < 1 or timeout > 60:
                    messagebox.showerror("Input Error", 
                        f"Invalid timeout value: {timeout}\n"
                        "Timeout must be between 1 and 60 seconds")
                    return
            except ValueError:
                messagebox.showerror("Input Error", 
                    f"Invalid timeout value: {timeout_str}\n"
                    "Please enter a valid number")
                return
            
            # Check network interface
            if not self.check_network_interface():
                result = messagebox.askyesno("Warning", 
                    "No network interface detected.\n"
                    "This may cause scanning issues.\n\n"
                    "Do you want to continue anyway?")
                if not result:
                    return
            
            # Check network connectivity
            if not self.check_network_connectivity():
                result = messagebox.askyesno("Warning", 
                    "Network connectivity issues detected.\n"
                    "Some devices may not respond to ARP requests.\n\n"
                    "Do you want to continue anyway?")
                if not result:
                    return
            
            # Check privileges
            if not self.check_scanning_privileges():
                result = messagebox.askyesno("Warning", 
                    "May need administrator privileges for optimal scanning.\n"
                    "If scan fails, try running with administrator rights.\n\n"
                    "Do you want to continue anyway?")
                if not result:
                    return
            
            # Clear previous results
            self.clear_results()
            
            # Update UI
            self.scanning = True
            self.scan_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            
            # Start scan thread
            self.scan_thread = threading.Thread(
                target=self.scan_network,
                args=(ip_range, timeout),
                daemon=True
            )
            self.scan_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start scan: {e}")
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def stop_scan(self):
        """Stop network scan"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.message_queue.put(("status", "Scan stopped"))
        self.message_queue.put(("progress", False))
    
    def clear_results(self):
        """Clear scan results"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.device_count_label.config(text="Devices found: 0")
        self.scan_time_label.config(text="")
    
    def process_messages(self):
        """Process messages from scan thread with enhanced error handling"""
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                
                if msg_type == "status":
                    self.status_label.config(text=data)
                elif msg_type == "progress":
                    if data:
                        self.progress_bar.start(10)
                    else:
                        self.progress_bar.stop()
                        # Re-enable scan button when scan completes
                        self.scanning = False
                        self.scan_button.config(state=tk.NORMAL)
                        self.stop_button.config(state=tk.DISABLED)
                elif msg_type == "result":
                    try:
                        ip, mac, vendor = data
                        self.tree.insert('', 'end', values=(ip, mac, vendor))
                        count = len(self.tree.get_children())
                        self.device_count_label.config(text=f"Devices found: {count}")
                    except Exception as e:
                        print(f"Error processing result: {e}")
                elif msg_type == "error":
                    messagebox.showerror("Scan Error", data)
                    self.stop_scan()
                elif msg_type == "warning":
                    messagebox.showwarning("Scan Warning", data)
                elif msg_type == "info":
                    messagebox.showinfo("Scan Info", data)
                
        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error processing messages: {e}")
        
        # Schedule next check
        self.root.after(100, self.process_messages)
    
    def create_tooltips(self):
        """Create tooltips for GUI elements"""
        self.create_tooltip(self.ip_range_entry, 
            "Enter the IP range to scan (e.g., 192.168.1.1/24)\n"
            "Common ranges:\n"
            "• 192.168.1.1/24 - Home networks\n"
            "• 10.0.0.1/24 - Corporate networks\n"
            "• 172.16.1.1/24 - Private networks")
        
        self.create_tooltip(self.timeout_entry,
            "Set scan timeout in seconds\n"
            "• 1 second: Fast scan\n"
            "• 3-5 seconds: More thorough\n"
            "• Higher values for slow networks")
        
        self.create_tooltip(self.scan_button,
            "Start scanning the network for active devices\n"
            "This will discover all devices on the specified IP range")
        
        self.create_tooltip(self.stop_button,
            "Stop the current scan operation\n"
            "Useful if scan is taking too long")
        
        self.create_tooltip(self.clear_button,
            "Clear all scan results from the table\n"
            "Useful before starting a new scan")
        
        self.create_tooltip(self.tree,
            "Scan results table\n"
            "• IP Address: Device IP\n"
            "• MAC Address: Device hardware address\n"
            "• Vendor: Device manufacturer\n"
            "Click column headers to sort")
    
    def create_tooltip(self, widget, text):
        """Create a tooltip for a widget"""
        def show_tooltip(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            
            label = tk.Label(tooltip, text=text, justify=tk.LEFT,
                           background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                           font=("Arial", 8, "normal"))
            label.pack()
            
            def hide_tooltip():
                tooltip.destroy()
            
            widget.tooltip = tooltip
            widget.bind('<Leave>', lambda e: hide_tooltip())
            widget.bind('<Button-1>', lambda e: hide_tooltip())
        
        widget.bind('<Enter>', show_tooltip)
    
    def show_help(self):
        """Show comprehensive help dialog"""
        help_text = """
🔍 NETWORK SCANNER GUI - HELP GUIDE

📋 QUICK START:
1. Enter IP range (e.g., 192.168.1.1/24)
2. Set timeout (1-5 seconds recommended)
3. Click "Start Scan"
4. View results in the table below

🎯 SCAN SETTINGS:

IP Range:
• 192.168.1.1/24 - Most home networks
• 10.0.0.1/24 - Corporate networks  
• 172.16.1.1/24 - Private networks
• Custom: Enter any valid IP range

Timeout:
• 1 second: Fast scan (recommended)
• 3-5 seconds: More thorough scan
• Higher values for slow networks

🔧 CONTROLS:

Start Scan:
• Begins network discovery
• Shows progress bar
• Results appear in real-time

Stop Scan:
• Interrupts current scan
• Useful for long scans

Clear Results:
• Removes all results
• Prepares for new scan

📊 RESULTS TABLE:

Columns:
• IP Address: Device IP (e.g., 192.168.1.10)
• MAC Address: Hardware address (e.g., 00:11:22:33:44:55)
• Vendor: Manufacturer name (e.g., Apple Inc.)

Features:
• Click column headers to sort
• Scroll to see more results
• Real-time device count

⚡ TIPS:

• Use /24 for most home networks
• Higher timeout = more thorough scan
• Results update in real-time
• Vendor info requires internet connection
• Stop scan if taking too long

🔒 SECURITY NOTES:

• Only scan networks you own
• Some networks may block scans
• Use responsibly and legally
• Results depend on network configuration

📞 TROUBLESHOOTING:

No devices found?
• Check IP range is correct
• Try increasing timeout
• Verify network connectivity

Scan errors?
• Check network permissions
• Try different IP range
• Restart application

Need more help?
• Check the README.md file
• Review command-line version
• Ensure proper dependencies
        """
        
        help_window = tk.Toplevel(self.root)
        help_window.title("Network Scanner Help")
        help_window.geometry("600x700")
        help_window.configure(bg='#f0f0f0')
        
        # Make window modal
        help_window.transient(self.root)
        help_window.grab_set()
        
        # Create text widget with scrollbar
        text_frame = ttk.Frame(help_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget = scrolledtext.ScrolledText(
            text_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg='white',
            fg='black'
        )
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        # Insert help text
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        close_button = ttk.Button(help_window, text="Close", command=help_window.destroy)
        close_button.pack(pady=10)
        
        # Center window
        help_window.update_idletasks()
        x = (help_window.winfo_screenwidth() // 2) - (help_window.winfo_width() // 2)
        y = (help_window.winfo_screenheight() // 2) - (help_window.winfo_height() // 2)
        help_window.geometry(f"+{x}+{y}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
Network Scanner GUI v1.0

A graphical interface for network device discovery.

Features:
• Network scanning with ARP requests
• Real-time device discovery
• MAC vendor identification
• User-friendly interface
• Threaded scanning (non-blocking UI)

Built with:
• Python 3.x
• tkinter (GUI framework)
• scapy (network scanning)
• requests (vendor lookup)

Author: Network Scanner Project
License: Educational Use

For command-line version, see main.py
        """
        
        messagebox.showinfo("About Network Scanner", about_text)
    
    def validate_ip_range(self, ip_range: str) -> bool:
        """Validate IP range format"""
        try:
            # Basic format check
            if '/' not in ip_range:
                return False
            
            ip_part, cidr_part = ip_range.split('/')
            
            # Check CIDR notation
            cidr = int(cidr_part)
            if cidr < 1 or cidr > 32:
                return False
            
            # Check IP format
            ip_parts = ip_part.split('.')
            if len(ip_parts) != 4:
                return False
            
            for part in ip_parts:
                if not part.isdigit() or int(part) < 0 or int(part) > 255:
                    return False
            
            return True
        except:
            return False
    
    def validate_mac_address(self, mac: str) -> bool:
        """Validate MAC address format"""
        import re
        pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(pattern.match(mac))
    
    def check_network_interface(self) -> bool:
        """Check if network interface is available"""
        try:
            return scapy.conf.iface is not None
        except:
            return False
    
    def check_network_connectivity(self) -> bool:
        """Check basic network connectivity"""
        try:
            import socket
            socket.gethostbyname("8.8.8.8")
            return True
        except:
            return False
    
    def check_scanning_privileges(self) -> bool:
        """Check if we have appropriate privileges for scanning"""
        try:
            import os
            if hasattr(os, 'geteuid'):
                return os.geteuid() == 0
            return True  # Assume OK on Windows
        except:
            return True
    
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Scan", command=self.start_scan, accelerator="Ctrl+N")
        file_menu.add_command(label="Stop Scan", command=self.stop_scan, accelerator="Ctrl+S")
        file_menu.add_separator()
        file_menu.add_command(label="Clear Results", command=self.clear_results, accelerator="Ctrl+L")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")
        
        # Scan menu
        scan_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="Quick Scan (192.168.1.1/24)", 
                            command=lambda: self.quick_scan("192.168.1.1/24"))
        scan_menu.add_command(label="Home Network (192.168.0.1/24)", 
                            command=lambda: self.quick_scan("192.168.0.1/24"))
        scan_menu.add_command(label="Corporate Network (10.0.0.1/24)", 
                            command=lambda: self.quick_scan("10.0.0.1/24"))
        scan_menu.add_separator()
        scan_menu.add_command(label="Custom Range...", command=self.custom_scan)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Export Results", command=self.export_results)
        tools_menu.add_command(label="Copy Selected", command=self.copy_selected)
        tools_menu.add_separator()
        tools_menu.add_command(label="Ping Test", command=self.ping_test)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Help", command=self.show_help, accelerator="F1")
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_separator()
        help_menu.add_command(label="View README", command=self.view_readme)
        
        # Bind keyboard shortcuts
        self.root.bind('<Control-n>', lambda e: self.start_scan())
        self.root.bind('<Control-s>', lambda e: self.stop_scan())
        self.root.bind('<Control-l>', lambda e: self.clear_results())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<F1>', lambda e: self.show_help())
    
    def quick_scan(self, ip_range):
        """Perform a quick scan with predefined range"""
        self.ip_range_var.set(ip_range)
        self.start_scan()
    
    def custom_scan(self):
        """Show dialog for custom scan settings"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Custom Scan Settings")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Create widgets
        ttk.Label(dialog, text="IP Range:").pack(pady=5)
        ip_entry = ttk.Entry(dialog, width=30)
        ip_entry.pack(pady=5)
        ip_entry.insert(0, self.ip_range_var.get())
        
        ttk.Label(dialog, text="Timeout (seconds):").pack(pady=5)
        timeout_entry = ttk.Entry(dialog, width=10)
        timeout_entry.pack(pady=5)
        timeout_entry.insert(0, self.timeout_var.get())
        
        def start_custom_scan():
            self.ip_range_var.set(ip_entry.get())
            self.timeout_var.set(timeout_entry.get())
            dialog.destroy()
            self.start_scan()
        
        ttk.Button(dialog, text="Start Scan", command=start_custom_scan).pack(pady=10)
        ttk.Button(dialog, text="Cancel", command=dialog.destroy).pack(pady=5)
    
    def export_results(self):
        """Export scan results to file"""
        if not self.tree.get_children():
            messagebox.showwarning("Export", "No results to export!")
            return
        
        try:
            filename = f"network_scan_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write("Network Scanner Results\n")
                f.write("=" * 50 + "\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"IP Range: {self.ip_range_var.get()}\n")
                f.write(f"Devices Found: {len(self.tree.get_children())}\n\n")
                
                f.write(f"{'IP Address':<16} {'MAC Address':<18} {'Vendor':<35}\n")
                f.write("-" * 80 + "\n")
                
                for item in self.tree.get_children():
                    values = self.tree.item(item)['values']
                    f.write(f"{values[0]:<16} {values[1]:<18} {values[2]:<35}\n")
            
            messagebox.showinfo("Export", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")
    
    def copy_selected(self):
        """Copy selected results to clipboard"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Copy", "No items selected!")
            return
        
        try:
            import pyperclip
            clipboard_text = ""
            for item in selected:
                values = self.tree.item(item)['values']
                clipboard_text += f"{values[0]}\t{values[1]}\t{values[2]}\n"
            
            pyperclip.copy(clipboard_text)
            messagebox.showinfo("Copy", f"Copied {len(selected)} items to clipboard")
        except ImportError:
            messagebox.showwarning("Copy", "pyperclip not installed. Install with: pip install pyperclip")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy: {e}")
    
    def ping_test(self):
        """Test connectivity to selected device"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Ping Test", "Please select a device first!")
            return
        
        item = selected[0]
        ip = self.tree.item(item)['values'][0]
        
        try:
            import subprocess
            result = subprocess.run(['ping', '-c', '3', ip], 
                                 capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                messagebox.showinfo("Ping Test", f"Successfully pinged {ip}\n\n{result.stdout}")
            else:
                messagebox.showwarning("Ping Test", f"Failed to ping {ip}\n\n{result.stderr}")
        except Exception as e:
            messagebox.showerror("Ping Error", f"Ping test failed: {e}")
    
    def view_readme(self):
        """Open README file in browser or text editor"""
        try:
            import webbrowser
            webbrowser.open('README.md')
        except:
            messagebox.showinfo("README", "README.md file not found in current directory")

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 