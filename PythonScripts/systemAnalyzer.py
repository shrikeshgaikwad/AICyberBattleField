import nmap

target = str(input("enter ip : "))
ports = "1000-10000"

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




# import nmap

# scanner = nmap.PortScanner()

# targetIp = "192.168.0.103"
# ports = "1000-8080"

# scanner.scan(hosts=targetIp,ports=ports)

# if targetIp in scanner.all_hosts():
#     protocols = scanner[targetIp].state()
#     print(protocols)

#     for proto in protocols:
#         scannedPorts = scanner[targetIp][proto].keys()
#         for port in sorted(scannedPorts):
#             state = scanner[targetIp][proto][port]['state']
#             print(state)

# else:
#     print("host down")



