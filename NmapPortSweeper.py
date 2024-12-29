#Made by MusicalVR
#Use with proper authorization
#This is for targeting ports and os guessing
#(A really helpful thing BTW)

import nmap

def port_sweep_and_device_detection(ip_range, ports):
    """
    Perform a port sweep and attempt to detect the OS and device type.

    Args:
        ip_range (str): The range of IP addresses to scan (e.g., "192.168.1.0/24").
        ports (str): The ports to scan (e.g., "1-1024" or "80,443").

    Returns:
        None
    """
    try:
        # Initialize the nmap scanner
        nm = nmap.PortScanner()

        print(f"Scanning IP range: {ip_range} on ports: {ports}...")
        
        # Run the nmap scan
        nm.scan(hosts=ip_range, ports=ports, arguments='-O')

        # Process and print the scan results
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")

            # Check for detected OS
            if 'osmatch' in nm[host]:
                for os in nm[host]['osmatch']:
                    print(f"OS Detected: {os['name']} (Accuracy: {os['accuracy']}%)")
            
            # List open ports
            print("Open Ports:")
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    state = nm[host]['tcp'][port]['state']
                    name = nm[host]['tcp'][port]['name']
                    print(f"  Port {port}/{name}: {state}")
            else:
                print("  No open TCP ports detected.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Define the IP range and ports to scan
    target_ip_range = input("Enter the target IP range (e.g., 192.168.1.0/24): ")
    target_ports = input("Enter the ports to scan (e.g., 1-1024, 80,443): ")

    # Execute the function
    port_sweep_and_device_detection(target_ip_range, target_ports)
