import socket
import concurrent.futures
import os


ip = input("Enter the IP address you want to scan: ")


start_port = 1
end_port = 1023


def port_scan(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect((ip, port))
        service = sock.recv(1024)
        sock.close()
        return (port, True, service.decode().strip())
    except:
        return (port, False, '')



def os_detection(ip):
    response = os.popen(f"ping {ip} -n 1").read()
    if "TTL=" in response:
        return "Windows"
    else:
        response = os.popen(f"ping {ip} -c 1").read()
        if "ttl=" in response:
            return "Linux/Unix"
        else:
            return "Unknown"





print("(...", "Scanning IP address:", ip, "...)")
print("Testing target ports 1 to 1023 to see if they are open...")
open_ports = []
with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = []
    for port in range(start_port, end_port + 1):
        futures.append(executor.submit(port_scan, ip, port))
    for future in concurrent.futures.as_completed(futures):
        port, is_open, service = future.result()
        if is_open:
            print(" ", "- Port", port, "is open. Running:", service)
            open_ports.append((port, service))

if len(open_ports) == 0:
    print("No open ports found on IP address", ip)
            

os = os_detection(ip)
print(" ")
print("-> [", "The operating system of the target is:", os, "] <-")
print(" ")

      
print("---- SCAN FINISHED ----")
