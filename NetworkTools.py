import socket
import tkinter as tk
import sys
import os
import struct
import time
import select
import binascii
from datetime import datetime
import dns.resolver
NUM_PACKETS = 4
ICMP_ECHO_REQUEST = 8
TIMEOUT = 5
MAX_HOPS = 30

# ICMP types
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

# Set same number as normal traceroute
MAX_HOPS = 64

def append_to_textarea(text):
    textarea.insert(tk.END, text + "\n")
    textarea.see(tk.END)  # Scroll the textarea to the end
    textarea.update_idletasks()

def calc_checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        checksum += (data[i] << 8) + data[i + 1]
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def create_packet(id, seq):
    # Create the ICMP packet
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, seq)
    data = b'Hello, world!'
    checksum = calc_checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum), id, seq)
    return header + data

def send_ping(dest_addr, time_to_live, id, seq):
    try:
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, time_to_live)
        packet = create_packet(id, seq)
        icmp_socket.sendto(packet, (dest_addr, 1))

        start_time = time.time()
        while True:
            icmp_socket.settimeout(TIMEOUT)
            try:
                reply, addr = icmp_socket.recvfrom(1024)
                end_time = time.time()
                elapsed_time = int((end_time - start_time) * 1000)
                return elapsed_time, addr[0]
            except socket.timeout:
                return None, None
    finally:
        icmp_socket.close()

def tracert(dest_host):
    try:
        dest_addr = socket.gethostbyname(dest_host)
        dest_domain = socket.gethostbyaddr(dest_addr)[0]
    except socket.gaierror:
        dest_addr = dest_host
        dest_domain = "N/A"

    append_to_textarea(f"Tracert to {dest_addr} ({dest_host}) over a maximum of {MAX_HOPS} hops")

    time_to_live = 1
    id = os.getpid() & 0xFFFF

    while time_to_live <= MAX_HOPS:
        elapsed_time, addr = send_ping(dest_addr, time_to_live, id, time_to_live)
        if addr:
            try:
                domain = socket.gethostbyaddr(addr)[0]
            except socket.herror:
                domain = "N/A"
            if addr == dest_addr:
                append_to_textarea(f"{time_to_live}\t{elapsed_time} ms\t{addr} ({dest_host})")
            else:
                append_to_textarea(f"{time_to_live}\t{elapsed_time} ms\t{addr} ({domain})")
        else:
            append_to_textarea(f"{time_to_live}\t*\t*")
        if addr == dest_addr:
            break
        time_to_live += 1

def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout
    while True:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)
        #recPacket là dữ liệu dưới dạng chuỗi bytes, addr là địa chỉ nguồn của gói tin nhận được

        icmp_header = recPacket[20:28]
        # header nằm từ vị trí 20 đến 27(8 bytes)

        rawTTL = struct.unpack("s", bytes([recPacket[8]]))[0]

       
        TTL = int.from_bytes(rawTTL, byteorder='big')
        

        icmpType, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmp_header)
        
        if packetID == ID:
            byte = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + byte])[0]
            return "Reply from %s: bytes=%d time=%dms TTL=%d" % (destAddr, len(recPacket), int((timeReceived - timeSent) * 1000), TTL)

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    
    header = struct.pack("BBHHH", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    # B đại diện cho unsigned char (1 byte), H đại diện cho unsigned short (2 byte)
    data = struct.pack("d", time.time())
    # data là thời gian hiện tại để thuận tiện cho việc tính delay time


    # value = struct.unpack('d', data)[0]
    # time_obj = datetime.fromtimestamp(value)
    # print(time_obj)

    # Calculate the checksum on the data and the dummy header.
    myChecksum = calc_checksum(header + data)


    myChecksum = socket.htons(myChecksum)
    #chuyển đổi giá trị của biến myChecksum sang định dạng network byte order để đảm bảo tính nhất quán khi truyền dữ liệu giữa các máy tính có kiến trúc khác nhau
    
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data

    mySocket.sendto(packet, (destAddr, 1))
    # (destAddr, 1) là tuple địa chỉ gồm địa chỉ đích và port 1

def doOnePing(destAddr, timeout):
    icmp = socket.getprotobyname("icmp")

    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                            # AF_INET cho biết socket sẽ làm việc với IPv4
                            # loại socket RAW, với loại này thì ứng dụng có thể tạo và gửi các gói tin mạng tùy chỉnh
                            # icmp là loại giao thức sử dụng
    myID = os.getpid() & 0xFFFF  # Return the current process i
    #os.getpid() là lấy ID của process đang chạy nhưng phải AND với 65535 để giới hạn ID trong phạm vi 16 bit
    # print("ID: " + str(myID))
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay


def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    min_delay = float('inf')
    max_delay = 0
    total_delay = 0
    successful_pings = 0
    try:
        dest = socket.gethostbyname(host)
        append_to_textarea("Pinging " + dest + ":")
        append_to_textarea("")
        # Send ping requests to a server separated by approximately one second
        for i in range(NUM_PACKETS):
            delay = doOnePing(dest, timeout)
            append_to_textarea(delay)
            if "Reply" in delay:
                successful_pings = successful_pings + 1
                delay_value = delay.split('=')[-2].split()[0]
                delay_time = int(''.join(filter(str.isdigit, delay_value)))
                total_delay += delay_time

                # Update minimum and maximum delays
                if delay_time < min_delay:
                    min_delay = delay_time
                if delay_time > max_delay:
                    max_delay = delay_time
            time.sleep(1)  # one second


        if successful_pings > 0:
            average_delay = total_delay / successful_pings
            min_delay = round(min_delay)
            max_delay = round(max_delay)
            average_delay = round(average_delay)
            append_to_textarea(f"Ping statistics for {dest}")
            append_to_textarea(f"Packets: Sent = {NUM_PACKETS}, Received = {successful_pings}, Lost = {NUM_PACKETS - successful_pings} ({100 * (NUM_PACKETS - successful_pings) / NUM_PACKETS}% loss)")
            append_to_textarea(f"Approximate round trip times in milli-seconds:")
            append_to_textarea(f"Minimum time = {min_delay} ms, Maximum time = {max_delay} ms, Average time = {average_delay} ms")
        return delay
    except socket.gaierror:
            append_to_textarea(f"Ping request could not find host {host}")

def nslookup(target):
    try:
        # Check if the input is an IP address
        if all(part.isdigit() and 0 <= int(part) <= 255 for part in target.split('.')):
            # Nslookup for IP address
            hostname = socket.gethostbyaddr(target)[0]
            append_to_textarea(f"Hostname for {target}: {hostname}")
        else:
            # Nslookup for domain
            ip_addresses = [str(ip) for ip in socket.gethostbyname_ex(target)[2]]
            append_to_textarea(f"IP Addresses for {target}: {', '.join(ip_addresses)}")

            # Nslookup for name servers
            answers = dns.resolver.resolve(target, 'NS')
            nameservers = [str(rdata) for rdata in answers]
            append_to_textarea(f"Name Servers for {target}: {', '.join(nameservers)}")

    except socket.herror:
        append_to_textarea(f"Failed to resolve hostname for {target}")
    except socket.gaierror:
        append_to_textarea(f"Failed to resolve IP address for {target}")
    except dns.resolver.NXDOMAIN:
        append_to_textarea(f"Domain does not exist: {target}")
    except dns.resolver.NoAnswer:
        append_to_textarea(f"No NS records found for {target}")

def button_clicked():
    selected_option = option_var.get()
    input_text = input_entry.get()
    textarea.delete("1.0", tk.END)  # Clear the textarea
    textarea.update_idletasks()
    if selected_option == 'traceroute':
        perform_tracert(input_text)
    elif selected_option == 'ping':
        ping(input_text)
    else: 
        nslookup(input_text)

def perform_tracert(host):
    try:
       tracert(host)
    except Exception as e:
        append_to_textarea(str(e))

last_command_end = "1.0"

def parse_and_execute_command(command):
    textarea.insert(tk.END, "\n")
    global last_command_end  # Sử dụng biến global để lưu vị trí cuối cùng của lệnh

    # Split the command by spaces
    command_parts = command.strip().split()

    # Check if the command has at least one part
    if command_parts:
        selected_command = command_parts[0]  # The first part is the command itself
        additional_arguments = command_parts[1:]  # Other parts are arguments
        if selected_command == 'ping':
            
            ping_result = ping(' '.join(additional_arguments))
            if ping_result:
                append_to_textarea(ping_result)
        elif selected_command == 'tracert':
            perform_tracert(' '.join(additional_arguments))
        elif selected_command == 'nslookup':
            nslookup(' '.join(additional_arguments))
        else:
            append_to_textarea("Command not recognized.")

        # Lưu vị trí cuối cùng của lệnh đã thực hiện
        last_command_end = textarea.index(tk.END)

def execute_command(event=None):
    global last_command_end  # Sử dụng biến global để lưu vị trí cuối cùng của lệnh

    # Get the text from the textarea for command execution
    command = textarea.get(last_command_end, tk.END).strip()  # Lấy lệnh từ vị trí cuối cùng của lệnh trước đó
    if command:
        parse_and_execute_command(command)
        # Cập nhật vị trí cuối cùng của lệnh để thực hiện lệnh tiếp theo
        last_command_end = textarea.index(tk.END)

window = tk.Tk()
window.title("My_basic_network_tools")
window.configure(bg='lightgray')

label = tk.Label(window, text="Features:", bg='lightgray', fg='black')
label.pack(pady=5, padx=10)

option_var = tk.StringVar()
option_var.set('ping')
option_menu = tk.OptionMenu(window, option_var, 'ping', 'traceroute', 'nslookup')
option_menu.pack(pady=5, padx=10)

input_entry = tk.Entry(window, bg='white', fg='black')
input_entry.pack(pady=5, padx=10)

textarea = tk.Text(window, bg='white', fg='black')
textarea.pack(pady=5, padx=10, expand=True, fill=tk.BOTH)

button = tk.Button(window, text="Run", command=button_clicked, bg='lightblue', fg='black')
button.pack(pady=5)
textarea.bind("<Return>", execute_command)
window.mainloop()