import sys
from tqdm import tqdm


def parse_ipv4_header(packet_data):
    # Ensure the packet data is at least 20 bytes (IPv4 header length)
    if (len(packet_data) < 40 ):  # Since the packet data is in hexadecimal, each byte is represented by 2 characters.
        raise ValueError(
            "Invalid packet data: IPv4 header length should be at least 20 bytes."
        )

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
    if (
        len(packet_data) != packet_length * 2
    ):  # *2 because each byte is represented by 2 characters in hexadecimal.
        raise ValueError("Packet length mismatch.")

    # Extract source and destination IP addresses
    source_ip_hex = packet_data[24:32]
    destination_ip_hex = packet_data[32:40]

    # Convert the hexadecimal IP addresses to dot-decimal notation
    source_ip = ".".join(str(int(source_ip_hex[i : i + 2], 16)) for i in range(0, 8, 2))
    destination_ip = ".".join(
        str(int(destination_ip_hex[i : i + 2], 16)) for i in range(0, 8, 2)
    )

    return {
        "version": ip_version,
        "header_length": header_length,
        "total_length": packet_length,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
    }


def main():
    
    with open('packets.txt', "r") as file:
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
    for packet_number, packet_data in tqdm(packets.items()):
        packet_number = int(packet_number)  # First line is the packet number
        packet_data = "".join(packet_data)  # Combine packet data

        # Extract data from the packet
        extracted_data = parse_ipv4_header(packet_data)

        # Display the extracted data
        for key, value in extracted_data.items():
            print(f"{key}: {value}")


if __name__ == "__main__":
    main()
