import socket
import struct

def main():
    try:
        snif_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("Error: Raw Socket needs root previledges.")
        print("Please run with 'sudo'.")
        return

    print("Started to Listening network...")

    try:
        while True:
            packet, addr = snif_socket.recvfrom(65535)
            
            #etherner header
            eth_header = packet[:14]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            # examine ethertype4
            if eth_protocol != 8:
                continue

            # 1. IP header
            ip_header_raw = packet[14:34]
            ip_header = struct.unpack("!BBHHHBBH4s4s", ip_header_raw)

            # 2.Protocol check
            protocol = ip_header[6]

            if protocol == 6:
                protocol_name = "TCP"
            elif protocol == 17:
                protocol_name = "UDP"
            elif protocol == 1:
                protocol_name = "ICMP"
            else:
                continue  # İskip 

            # 3.IP address
            src_ip = socket.inet_ntoa(ip_header[8])
            dest_ip = socket.inet_ntoa(ip_header[9])

            # 4. IHL calc
            ihl = ip_header[0] & 0xF
            ip_header_length = ihl * 4

            # i forgot sorry :D 
            transport_offset = 14 + ip_header_length

            # 6. Ports
            if protocol == 6 or protocol == 17:
                # 2 byte src port + 2 byte dest port
                ports_raw = packet[transport_offset : transport_offset + 4]
                
                # '!HH' -> !: Big-Endian, H: Unsigned Short (2 byte)
                ports = struct.unpack("!HH", ports_raw)
                
                src_port = ports[0]
                dest_port = ports[1]
                
                print(f"Source: {src_ip}:{src_port} -> Destination: {dest_ip}:{dest_port} | Protokol: {protocol_name}")
                
            elif protocol == 1:
                print(f"Source: {src_ip} -> Destination: {dest_ip} |")

    except KeyboardInterrupt:
        print("\nEnded to Listening.")

if __name__ == "__main__":
    main()
