# Linux Firewall with Log Anomaly Detection

This project is a **hybrid firewall system** consisting of:  
- A **C++ firewall controller** that manages Linux `iptables` rules using a simple rules file.  
- A **Python log analyzer** that monitors firewall logs and detects anomalies using machine learning.  


---

## 🚀 Features

### **C++ Firewall (`iptables_firewall.cpp`)**
- Applies **iptables rules** directly on Linux.  
- Base policies:  
  - `INPUT = DROP`, `FORWARD = DROP`, `OUTPUT = ACCEPT`  
  - Allows loopback & established connections  
- Reads rules from `rules.txt` in the format:  

## 📑 Example Rules File (`rules.txt`)
ALLOW 192.168.1.10
BLOCK 203.0.113.45
ALLOW 10.0.0.0/24
BLOCK 198.51.100.0/24

---

## 🖥️ CLI Options

```bash
sudo ./ipfw --apply rules.txt    # Apply rules on top of base policy
sudo ./ipfw --rebuild rules.txt  # Flush & reapply rules
sudo ./ipfw --list               # Show active rules
sudo ./ipfw --flush              # Flush rules
```
---

## Python Log Analyzer (firewall_logger.py)

- Logs firewall events into firewall.log.
- Uses TF-IDF + KMeans clustering to detect unusual log messages.
- Helps identify suspicious or rare patterns in firewall activity.

# Run with:
```bash
 python3 firewall_logger.py
```

---

## ⚡ Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/sutharshan-xyz/Linux-Firewall.git
cd Linux-Firewall
```

### 2. Build the firewall
```bash 
g++ -std=c++17 -O2 -Wall -o ipfw iptables_firewall.cpp
```

### 3. Apply firewall rules
```bash
sudo ./ipfw --apply rules.txt
```
### 4. Analyze logs
```bash
python3 firewall_logger.py
```
