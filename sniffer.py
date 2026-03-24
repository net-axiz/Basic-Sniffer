import socket
import struct

def main():
    try:
        snif_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("Hata: Raw socket açmak için root yetkisi gereklidir.")
        print("Lütfen betiği 'sudo' ile çalıştırın.")
        return

    print("Ağ trafiği dinleniyor...")

    try:
        while True:
            packet, addr = snif_socket.recvfrom(65535)
            
            #Ethernet başlığını  çözümle
            eth_header = packet[:14]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            # Sadece IPv4 paketlerini (EtherType 8) işle, diğerlerini atla
            if eth_protocol != 8:
                continue

            # 1. IP Başlığını Çekme (İlk 14 byte Ethernet başlığını atlıyoruz)
            ip_header_raw = packet[14:34]
            ip_header = struct.unpack("!BBHHHBBH4s4s", ip_header_raw)

            # 2. Protokol Kontrolü (Sadece TCP, UDP ve ICMP ile ilgileniyoruz)
            protocol = ip_header[6]

            if protocol == 6:
                protocol_name = "TCP"
            elif protocol == 17:
                protocol_name = "UDP"
            elif protocol == 1:
                protocol_name = "ICMP"
            else:
                continue  # İlgilenmediğimiz protokolleri atla ve döngünün başına dön

            # 3. IP Adreslerini Çözümleme
            src_ip = socket.inet_ntoa(ip_header[8])
            dest_ip = socket.inet_ntoa(ip_header[9])

            # 4. Dinamik IP Başlık Uzunluğunu (IHL) Hesaplama
            ihl = ip_header[0] & 0xF
            ip_header_length = ihl * 4

            # 5. Taşıma Katmanının (TCP/UDP) Başlangıç Noktasını Bulma
            transport_offset = 14 + ip_header_length

            # 6. Port Numaralarını Çekme
            if protocol == 6 or protocol == 17:
                # TCP ve UDP'nin ilk 4 byte'ını alıyoruz (2 byte src port + 2 byte dest port)
                ports_raw = packet[transport_offset : transport_offset + 4]
                
                # '!HH' -> !: Big-Endian, H: Unsigned Short (2 byte)
                ports = struct.unpack("!HH", ports_raw)
                
                src_port = ports[0]
                dest_port = ports[1]
                
                print(f"Kaynak: {src_ip}:{src_port} -> Hedef: {dest_ip}:{dest_port} | Protokol: {protocol_name}")
                
            elif protocol == 1:
                # ICMP'de port numarası yoktur, sadece IP'leri yazdırıyoruz
                print(f"Kaynak: {src_ip} -> Hedef: {dest_ip} |")

    except KeyboardInterrupt:
        print("\nDinleme sonlandırıldı.")

if __name__ == "__main__":
    main()