# 🔍 Network Scanner GUI

A modern, user-friendly graphical interface for network device discovery. Discover active devices on your network with real-time scanning, vendor identification, and professional-grade features.

## ✨ Features

### 🖥️ **Modern Interface**
- **Clean Design**: Professional, intuitive GUI
- **Real-time Updates**: See devices as they're discovered
- **Progress Indicators**: Visual feedback during scans
- **Tooltips**: Hover for instant help on any element

### 🔍 **Network Discovery**
- **ARP-based Scanning**: Fast and reliable device detection
- **Vendor Identification**: Automatic manufacturer lookup
- **MAC Address Display**: Complete hardware information
- **IP Address Mapping**: Network topology visualization

### 📊 **Results Management**
- **Sortable Table**: Click headers to sort results
- **Export Functionality**: Save scans to timestamped files
- **Copy to Clipboard**: Copy selected devices
- **Device Counter**: Real-time count updates

### ⚡ **Advanced Features**
- **Multiple Scan Types**: Quick, custom, and predefined ranges
- **Ping Testing**: Test connectivity to discovered devices
- **Keyboard Shortcuts**: Power user efficiency
- **Error Handling**: Comprehensive validation and recovery

## 🚀 Quick Start

### **Installation**
```bash
# Install dependencies
pip install -r requirements.txt

# Run the GUI
python gui_scanner.py
```

### **First Scan**
1. **Launch** the application
2. **Enter IP range** (default: 192.168.1.1/24)
3. **Set timeout** (1-5 seconds recommended)
4. **Click "Start Scan"**
5. **Watch results** appear in real-time

## 🖥️ Interface Guide

### **Main Window**
```
┌─────────────────────────────────────────────────────────┐
│                    Network Scanner                      │
├─────────────────────────────────────────────────────────┤
│ Scan Settings:                                         │
│ IP Range: [192.168.1.1/24]  Timeout: [1] seconds     │
├─────────────────────────────────────────────────────────┤
│ [Start Scan] [Stop Scan] [Clear Results] [Help]       │
├─────────────────────────────────────────────────────────┤
│ Status: Ready to scan                                  │
│ ████████████████████████████████████████████████████  │
├─────────────────────────────────────────────────────────┤
│ Scan Results:                                          │
│ ┌─────────────┬──────────────────┬────────────────────┐ │
│ │ IP Address  │ MAC Address      │ Vendor             │ │
│ ├─────────────┼──────────────────┼────────────────────┤ │
│ │ 192.168.1.1 │ 00:11:22:33:44:55│ Router Manufacturer│ │
│ │ 192.168.1.10│ 11:22:33:44:55:66│ Apple Inc.        │ │
│ └─────────────┴──────────────────┴────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│ Devices found: 2                    Scan time: 1.2s   │
└─────────────────────────────────────────────────────────┘
```

## 🎯 Usage Guide

### **Basic Scanning**
- **Default Scan**: Click "Start Scan" with default settings
- **Custom Range**: Enter your network range (e.g., 10.0.0.1/24)
- **Timeout Adjustment**: Set scan duration (1-60 seconds)
- **Stop Scan**: Interrupt ongoing scans anytime

### **Menu Commands**

#### **File Menu**
- `Ctrl+N` - Start new scan
- `Ctrl+S` - Stop current scan
- `Ctrl+L` - Clear results
- `Ctrl+Q` - Exit application

#### **Scan Menu**
- **Quick Scan (192.168.1.1/24)** - Common home network
- **Home Network (192.168.0.1/24)** - Alternative home range
- **Corporate Network (10.0.0.1/24)** - Business networks
- **Custom Range...** - Advanced configuration

#### **Tools Menu**
- **Export Results** - Save to text file
- **Copy Selected** - Copy to clipboard
- **Ping Test** - Test device connectivity

#### **Help Menu**
- `F1` - Comprehensive help guide
- **About** - Program information
- **View README** - Open documentation

### **Keyboard Shortcuts**
| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | Start new scan |
| `Ctrl+S` | Stop current scan |
| `Ctrl+L` | Clear results |
| `Ctrl+Q` | Quit application |
| `F1` | Show help |

## 🔧 Advanced Features

### **Custom Scan Configuration**
1. Go to **Scan → Custom Range...**
2. Enter IP range (e.g., `192.168.1.1/24`)
3. Set timeout value (1-60 seconds)
4. Click **Start Scan**

### **Exporting Results**
1. Complete a scan
2. Go to **Tools → Export Results**
3. Results saved as `network_scan_YYYYMMDD_HHMMSS.txt`

### **Ping Testing**
1. Select a device from results
2. Go to **Tools → Ping Test**
3. View connectivity results

### **Copying Results**
1. Select devices (Ctrl+click for multiple)
2. Go to **Tools → Copy Selected**
3. Paste into any application

## 📊 Understanding Results

### **IP Address**
- Device's network address
- Example: `192.168.1.10`

### **MAC Address**
- Hardware address (unique identifier)
- Example: `00:11:22:33:44:55`

### **Vendor**
- Device manufacturer
- Examples: `Apple Inc.`, `Samsung Electronics`, `Unknown`

## ⚡ Performance Tips

### **Optimal Settings**
- **Timeout**: 1 second for fast scans, 3-5 for thorough
- **IP Range**: Use `/24` for most networks (254 devices max)
- **Network Type**: Adjust based on your network size

### **Common IP Ranges**
- `192.168.1.1/24` - Most home networks
- `192.168.0.1/24` - Alternative home networks
- `10.0.0.1/24` - Corporate networks
- `172.16.1.1/24` - Private networks

## 🐛 Troubleshooting

### **Common Issues**

#### **"No devices found"**
- Verify IP range is correct for your network
- Try increasing timeout to 3-5 seconds
- Check network connectivity
- Try different IP ranges

#### **"Permission denied"**
- Run with administrator/sudo privileges
- Check firewall settings
- Verify network interface permissions

#### **"Scan errors"**
- Check internet connection (for vendor lookup)
- Verify scapy installation: `pip install scapy`
- Try restarting the application

#### **"GUI not responding"**
- Scans run in background threads
- Use "Stop Scan" if taking too long
- Check system resources

### **Getting Help**
1. **Press F1** for comprehensive help
2. **Hover over elements** for tooltips
3. **Check the console** for error messages
4. **Review network configuration**

## 🔒 Security & Legal

### **Important Notes**
- **Only scan networks you own or have permission to scan**
- **Some networks may block or detect scans**
- **Use responsibly and legally**
- **Results depend on network configuration**

### **Best Practices**
- Test on your own network first
- Use appropriate timeouts to avoid network disruption
- Respect network policies and regulations
- Document your findings appropriately

## 📁 File Structure

```
network-scanner/
├── gui_scanner.py      # Main GUI application
├── main.py             # Command-line version
├── macChanger.py       # MAC address changer
├── requirements.txt    # Python dependencies
└── README.md          # This documentation
```

## 🛠️ Requirements

- **Python 3.6+**
- **Network privileges** (may require sudo/administrator)
- **Internet connection** (for vendor lookup)

### **Dependencies**
```
scapy>=2.4.5
requests>=2.25.1
```

## 🤝 Contributing

1. Create a feature branch
2. Make your changes
3. Test thoroughly
4. Submit your improvements

## 📄 License

This project is for educational purposes. Use responsibly and in accordance with local laws and network policies.

## 🙏 Acknowledgments

- **scapy**: Network packet manipulation
- **tkinter**: GUI framework
- **macvendors.com**: MAC address vendor database
- **Python community**: Open source contributions

---

**Happy Scanning!** 🔍

*Remember: Always scan responsibly and only on networks you own or have permission to scan.* 
