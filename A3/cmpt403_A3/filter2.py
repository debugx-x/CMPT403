import sys
from tqdm import tqdm

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 filter.py <option> <filename>")
        sys.exit(1)

    option = sys.argv[1]
    filename = sys.argv[2]


    with open(filename, 'r') as file:
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
            packets[current_packet].append(line)

    # loop over packet in packets
    for packet_number, packet_data in tqdm(packets.items()):
        print(packet_number)
        print(packet_data)



if __name__ == "__main__":
    main()
