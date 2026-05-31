import socket
import struct
import sys

def main():
    # Setup raw socket for Linux/Termux (Requires root/sudo privileges)
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        print("[-] Permission Denied. Please run this script with elevated/root privileges (sudo python sniffer.py).")
        sys.exit(1)
        
    print("[*] Raw TCP Packet Sniffer Initialized. Capturing traffic...")
    
    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            
            print(f"\n[+] IP Packet: Protocol: {protocol} | TTL: {ttl} | Source: {s_addr} -> Dest: {d_addr}")
            
            # Unpack TCP header
            tcp_header = raw_data[iph_length:iph_length+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            
            print(f"  --> TCP Segment: Source Port: {source_port} | Dest Port: {dest_port} | Seq: {sequence} | Ack: {acknowledgement}")
    except KeyboardInterrupt:
        print("\n[*] Sniffing process stopped.")

if __name__ == "__main__":
    main()