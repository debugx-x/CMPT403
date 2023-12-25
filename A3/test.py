import struct

def extract_packet_data(packet_data):
    # The format string for unpacking the packet's header fields using 'struct'
    packet_format = ">BBHHHBBH4s4s"
    icmp_format = "BBH"

    # Unpack the fixed-length header fields
    version_header_length, dsf_tos, total_length, identification, flags_frag_offset, ttl, protocol, checksum, source_ip, dest_ip = struct.unpack(packet_format, bytes.fromhex(packet_data[:40]))

    # Extracting individual fields from version_header_length
    version = version_header_length >> 4
    header_length = (version_header_length & 0x0F) * 4  # Convert to bytes

    # Unpack ICMP header fields if the protocol is ICMP (1)
    if protocol == 1:
        icmp_type, icmp_code, icmp_checksum = struct.unpack(icmp_format, bytes.fromhex(packet_data[header_length:header_length + 4]))
        icmp_identifier, icmp_sequence_number = struct.unpack(">HH", bytes.fromhex(packet_data[header_length + 4:header_length + 8]))
        icmp_payload = packet_data[header_length + 8:]

    # Return the extracted data as a dictionary
    extracted_data = {
        "Version": version,
        "Header Length": header_length,
        "DSF/TOS": dsf_tos,
        "Total Length": total_length,
        "Identification": identification,
        "Flags and Fragment Offset": flags_frag_offset,
        "TTL": ttl,
        "Protocol": protocol,
        "Checksum": checksum,
        "Source IP": '.'.join(str(b) for b in source_ip),
        "Destination IP": '.'.join(str(b) for b in dest_ip),
    }

    # If the protocol is ICMP, add ICMP-specific data to the extracted_data dictionary
    if protocol == 1:
        extracted_data["ICMP Type"] = icmp_type
        extracted_data["ICMP Code"] = icmp_code
        extracted_data["ICMP Checksum"] = icmp_checksum
        extracted_data["ICMP Identifier"] = icmp_identifier
        extracted_data["ICMP Sequence Number"] = icmp_sequence_number
        extracted_data["ICMP Payload"] = icmp_payload

    return extracted_data

# Sample packet data (hexadecimal representation)
packet_data = '45000054005500004001d1a9010203048e3a166b0800d0b600d2000364b1d89e0000000000002a5100000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'

# Extract data from the packet
extracted_data = extract_packet_data(packet_data)
print(extracted_data)
