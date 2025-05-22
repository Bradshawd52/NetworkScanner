from flask import Flask, render_template, request
import socket
import ipaddress
import subprocess
import platform
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

def get_local_network():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)) 
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    network_base = local_ip.rsplit('.', 1)[0] + '.0/24' 
    return network_base

def is_alive(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', str(ip)]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def scan_ports(ip, ports=[80]): # 22, 80, 443, 3389
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((str(ip), port)) == 0:
                    open_ports.append(port)
        except:
            pass
    return open_ports

def scan_ip(ip):
    result = {'ip': str(ip), 'ports': [], 'error': None}
    
    try:
        if is_alive(ip):
            open_ports = scan_ports(ip)
            result['ports'] = open_ports if open_ports else ['No common ports open']
        else:
            result['error'] = f"{ip} is down"
    except Exception as e:
        result['error'] = f"Error scanning {ip}: {str(e)}"
    
    return result

def network_scan(network, results):
    net = ipaddress.ip_network(network, strict=False)
    threads = []
    for ip in net.hosts():
        t = threading.Thread(target=scan_ip, args=(ip, results))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    network = get_local_network()

    if request.method == 'POST':
        custom_range = request.form.get('network')
        network = custom_range if custom_range else network

        try:
            net = ipaddress.ip_network(network, strict=False)
            print(f"Scanning network {network}...")

            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_ip = {executor.submit(scan_ip, ip): ip for ip in net.hosts()}

                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        print(f"Error scanning{ip}: {e}")
                        results.append({'ip': str(ip), 'ports': ['Error scanning IP']})

        except ValueError as e:
            results.append({'ip': 'Error', 'ports': [f'Invalid network range: {e}']})

    return render_template('index.html', network=network, results=results)


if __name__ == "__main__":
    app.run(debug=True)
