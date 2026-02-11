import nmap

vulnerabilities = {}

def run_scan():
    target = str(input("enter ip : "))
    ports = "0-10000"

    scanner = nmap.PortScanner()

    print(f"Scanning started for {target}")
    scanner.scan(target, ports)

    if target in scanner.all_hosts():
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    state = scanner[host][proto][port]['state']
                    vulnerabilities.update({"Port": port, "State": state})
    else:
        print("host down")

if __name__ == "__main__":
    run_scan()
