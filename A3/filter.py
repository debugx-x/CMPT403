import sys
import ipaddress

def extract_packet_data(packet_data):
    # Ensure the packet data is at least 20 bytes (IPv4 header length)
    if (len(packet_data) < 40 ):  # Since the packet data is in hexadecimal, each byte is represented by 2 characters.
        raise ValueError("Invalid packet data: IPv4 header length should be at least 20 bytes.")

    # Extract the first byte and interpret it as IPv4 version and header length
    first_byte = int(packet_data[0:2], 16)
    ip_version = first_byte >> 4
    header_length = (first_byte & 0x0F) * 4  # Header length in bytes

    # Ensure it's a valid IPv4 packet
    if ip_version != 4 or header_length < 20:
        raise ValueError("Invalid IPv4 packet.")

    # Extract the total length of the packet (including the header)
    packet_length_hex = packet_data[4:8]
    packet_length = int(packet_length_hex, 16)

    # Ensure the packet data length matches the indicated packet length
    if (len(packet_data) != packet_length * 2):  # *2 because each byte is represented by 2 characters in hexadecimal.
        raise ValueError("Packet length mismatch.")
    
    # extract protocol
    protocol = int(packet_data[18:20], 16)

    # Extract source and destination IP addresses
    source_ip_hex = packet_data[24:32]
    destination_ip_hex = packet_data[32:40]

    # Convert the hexadecimal IP addresses to dot-decimal notation
    source_ip = ".".join(str(int(source_ip_hex[i : i + 2], 16)) for i in range(0, 8, 2))
    destination_ip = ".".join(str(int(destination_ip_hex[i : i + 2], 16)) for i in range(0, 8, 2))

    # Check if the protocol is TCP (6)
    if protocol == 6:
        # Extract source and destination ports
        source_port_hex = packet_data[40:44]
        destination_port_hex = packet_data[44:48]
        source_port = int(source_port_hex, 16)
        destination_port = int(destination_port_hex, 16)

        # Extract TCP flags
        packet_bytes = bytes.fromhex(packet_data)
        ihl = packet_bytes[0] & 0xF
        tcp_flags = packet_bytes[ihl * 4:ihl * 4 + 20][13]
        #tcp_flags_hex = packet_data[48:50]
        #tcp_flags = int(tcp_flags_hex, 16)

        return {
            "version": ip_version,
            "header_length": header_length,
            "total_length": packet_length,
            "protocol": protocol,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "tcp_flags": tcp_flags,
        }
    else:
        return {
            "version": ip_version,
            "header_length": header_length,
            "total_length": packet_length,
            "protocol": protocol,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
        }


def is_packet_valid(ip_addr):

    # Define the subnet to be allowed (142.58.22.0/24)
    allowed_subnet = ipaddress.IPv4Network("142.58.22.0/24")

    # Check if both source and destination IPs belong to the allowed subnet
    if (ipaddress.IPv4Address(ip_addr) in allowed_subnet):
        return True  # Valid packet
    else:
        return False  # Malicious packet

def extract_max_offset(packet_data):
    # Extracting the fragment offset and flags field from the packet data
    fragment_offset_flags = int(packet_data[12:16], 16)
    
    # Extracting the fragment offset value (first 13 bits)
    fragment_offset = fragment_offset_flags & 0x1FFF
    
    return fragment_offset

def is_ping_of_death(packet_data):
    # Extracting the total length of the packet from the packet data
    total_length = int(packet_data[4:8], 16)
    
    # Extracting the maximum offset value from the packet data
    fragment_offset = extract_max_offset(packet_data)
    
    # Calculating the value to compare with the threshold (65535)
    comparison_value = total_length + (fragment_offset * 8)

    # Checking if the condition for Ping of Death attack is met
    return comparison_value > 65535
    
# Two ping attacks filter
def ping_attacks_filter(ip_version, dst_ip, protocol, packet_lines):
    """Filter out pings of death and smurf attacks targeting hosts in the specified subnet."""

    # Check for ICMP echo (ping) packets
    if ip_version == 4 and protocol == 1:
        # Filter out pings of death (large offset)
        if is_ping_of_death(packet_lines):
            return "no"

        # Filter out smurf attacks (ping to broadcast address)
        subnet = ipaddress.IPv4Network("142.58.22.0/24")
        if dst_ip == subnet.network_address or dst_ip == subnet.broadcast_address:
            return "no"
        
    return "yes"

def is_syn_packet(packet_flags):
    return (packet_flags & 0x02) != 0

def is_ack_packet(packet_flags):
    return (packet_flags & 0x10) != 0

def is_rst_packet(packet_flags):
    return (packet_flags & 0x04) != 0

def is_fin_packet(packet_flags):
    return (packet_flags & 0x01) != 0

# Dictionary to keep track of half-open connections per IP
half_open_connections = {}

# SYN floods filter
def syn_floods_filter(extracted_data, max_half_open_connections):
    """Filter out SYN floods from outside IPs attempting more than the specified half-open connections."""

    source_ip = extracted_data["source_ip"]
    packet_flags = extracted_data["flags"]

    # Check for TCP packets
    if extracted_data["version"] == 4 and extracted_data["protocol"] == 6:
        if is_packet_valid(source_ip):
            if is_syn_packet(packet_flags):
                if source_ip not in half_open_connections:
                    half_open_connections[source_ip] = 1
                else:
                    half_open_connections[source_ip] += 1
                
                if half_open_connections[source_ip] > max_half_open_connections:
                    return "no"
                
            elif is_ack_packet(packet_flags) or is_rst_packet(packet_flags) or is_fin_packet(packet_flags):
                if source_ip in half_open_connections and half_open_connections[source_ip] > 0:
                    half_open_connections[source_ip] -= 1
    return "yes"
        

def main():
    # Check if the correct number of arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python filter.py <option> <filename>")
        sys.exit(1)

    option = sys.argv[1]
    filename = sys.argv[2]

    with open(filename, "r") as file:
        lines = file.readlines()

    packets = {}
    current_packet = None

    # read line by line
    for line in lines:
        line = line.strip()

        if line.isdigit():
            current_packet = int(line)
            packets[current_packet] = []
        else:
            packets[current_packet].append(line.split(":")[1].strip().replace(" ", ""))

    # loop over packet in packets
    for packet_number, packet_data in packets.items():
        packet_number = int(packet_number)  # First line is the packet number
        packet_data = "".join(packet_data)  # Combine packet data

        # Extract data from the packet
        extracted_data = extract_packet_data(packet_data)

        # Display the extracted data
        #for key, value in extracted_data.items():
            #print(f"{key}: {value}")

        # Egress filter
        if option == "-i":
            if is_packet_valid(extracted_data["source_ip"]):
                print(f"{packet_number} no")
            else:
                print(f"{packet_number} yes")
        
        # Two ping attacks filter
        elif option == "-j":
            print(f"{packet_number} {ping_attacks_filter(extracted_data['version'], extracted_data['destination_ip'], extracted_data['protocol'], packet_data)}")
        
        # SYN floods filter
        elif option == "-k":
            print(f"{packet_number} {syn_floods_filter(extracted_data, 10)}")

if __name__ == "__main__":
    main()
