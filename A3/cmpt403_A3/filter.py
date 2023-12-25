import sys
import ipaddress

def parse_packet(packet_data):
    """Parse the packet data and extract IP addresses, protocol, and other relevant information."""
    ip_version = int(packet_data[:1], 16) >> 4
    src_ip = '.'.join(str(int(packet_data[i:i + 2], 16)) for i in range(12, 20, 2))
    dst_ip = '.'.join(str(int(packet_data[i:i + 2], 16)) for i in range(20, 28, 2))
    protocol = int(packet_data[9:10], 16)
    return ip_version, src_ip, dst_ip, protocol

def is_valid_subnet(ip_str, subnet_str):
    """Check if the given IP is in the specified subnet."""
    ip = ipaddress.IPv4Address(ip_str)
    subnet = ipaddress.IPv4Network(subnet_str, strict=False)
    return ip in subnet

def egress_filter(packet_lines, subnet):
    """Egress packet filter that filters out packets not originating from the specified subnet."""
    ip_version, src_ip, _, _ = parse_packet(packet_lines)
    return "yes" if ip_version == 4 and not is_valid_subnet(src_ip, subnet) else "no"

def ping_attacks_filter(packet_lines, subnet):
    """Filter out pings of death and smurf attacks targeting hosts in the specified subnet."""
    ip_version, src_ip, dst_ip, protocol = parse_packet(packet_lines)

    # Check for ICMP echo (ping) packets
    if ip_version == 4 and protocol == 1:
        # Filter out pings of death (large offset)
        if packet_lines[5].startswith("\t0x0020:  48"):
            return "yes"

        # Filter out smurf attacks (ping to broadcast address)
        if is_valid_subnet(dst_ip, subnet) and dst_ip.endswith(".255"):
            return "yes"

    return "no"

def syn_floods_filter(packet_lines, max_half_open_connections):
    """Filter out SYN floods from outside IPs attempting more than the specified half-open connections."""
    ip_version, _, dst_ip, protocol = parse_packet(packet_lines)

    # Check for TCP SYN packets
    if ip_version == 4 and protocol == 6 and packet_lines[5].startswith("\t0x0020:  02"):
        # Count number of half-open connections from the same outside IP
        current_ip_connections = sum(1 for p in packet_lines if p[1][1] == dst_ip and p[2].startswith("\t0x0020:  02"))
        return "yes" if current_ip_connections >= max_half_open_connections else "no"

    return "no"

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 filter.py <option> <filename>")
        sys.exit(1)

    option = sys.argv[1]
    filename = sys.argv[2]

    # Read packet data from the file
    with open(filename, 'r') as file:
        lines = file.readlines()

    # Group lines into packets based on the packet number (the lines starting with a number)
    packets = []
    current_packet = []
    for line in lines:
        if line.strip().isdigit():
            if current_packet:
                packets.append(current_packet)
            current_packet = [line.strip()]
        else:
            current_packet.append(line.strip())
    if current_packet:
        packets.append(current_packet)

    # Apply the appropriate filter based on the selected option
    if option == "-i":
        subnet = "142.58.22.0/24"
        results = [egress_filter(packet, subnet) for packet in packets]
    elif option == "-j":
        subnet = "142.58.22.0/24"
        results = [ping_attacks_filter(packet, subnet) for packet in packets]
    elif option == "-k":
        max_half_open_connections = 10
        results = [syn_floods_filter(packet, max_half_open_connections) for packet in packets]
    else:
        print("Invalid option. Please use -i, -j, or -k.")
        sys.exit(1)

    # Print the results
    for i, result in enumerate(results, start=1):
        print(f"{i} {result}")

if __name__ == "__main__":
    main()
