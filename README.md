# Network Traffic Taxi

A lightweight Python CLI tool to monitor network traffic, built with `scapy`.  
Capture IP, TCP, UDP, and HTTP details, including full URLs, parameters, and headers right from your terminal.

### Features
✅ Monitors all network traffic on a chosen interface.  
✅ Parses HTTP requests (port 80) for method, URL, params, and headers.  
✅ Filters packets by string with the `-s` flag.  
✅ Cross-platform: Lists GUIDs + IPs on Windows, simple names on Linux.  
✅ Funny taxi banner to kick off your sniffing ride!  

### Usage
```bash
python taxi.py [-i <interface>] [-s <string>]