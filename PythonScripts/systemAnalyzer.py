import nmap

target = "192.168.0.105"
ports = "0-9000"

scanner = nmap.PortScanner()

print(f"Scannig started for {target}")


scanner.scan(target,ports)
for host in scanner.all_hosts():
    print("Host:", host)
    print("State:", scanner[host].state())

    for proto in scanner[host].all_protocols():
        print("Protocol:", proto)

        ports = scanner[host][proto].keys()
        for port in ports:
            state = scanner[host][proto][port]['state']
            print(f"Port {port}: {state}")