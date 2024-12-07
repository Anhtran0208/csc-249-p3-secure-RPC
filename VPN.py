#!/usr/bin/env python3

import socket
import arguments
import argparse

# Run 'python3 VPN.py --help' to see what these lines do
parser = argparse.ArgumentParser('Send a message to a server at the given address and prints the response')
parser.add_argument('--VPN_IP', help='IP address at which to host the VPN', **arguments.ip_addr_arg)
parser.add_argument('--VPN_port', help='Port number at which to host the VPN', **arguments.vpn_port_arg)
args = parser.parse_args()

VPN_IP = args.VPN_IP  # Address to listen on
VPN_PORT = args.VPN_port  # Port to listen on (non-privileged ports are > 1023)

def parse_message(message):
    message = message.decode("utf-8")
    # Parse the application-layer header into the destination SERVER_IP, destination SERVER_PORT,
    # and message to forward to that destination
    # raise NotImplementedError("Your job is to fill this function in. Remove this line when you're done.")
    SERVER_IP = message[:message.index('~IP~')]
    SERVER_PORT = int(message[message.index('~IP~')+4:message.index('~port~')])
    message = message[message.index('~port~')+6:]
    return SERVER_IP, SERVER_PORT, message

print("VPN starting - listening for connections at IP", VPN_IP, "and port", VPN_PORT)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.bind((VPN_IP, VPN_PORT))
    client_socket.listen()
    client_conn, client_addr = client_socket.accept()
    with client_conn:
        print(f"Connected established with {client_addr}")
        data = client_conn.recv(1024)
        print(f"Received client message: '{data!r}' [{len(data)} bytes]")
        SERVER_IP, SERVER_PORT, message = parse_message(data)
        print("connecting to server at IP", SERVER_IP, "and port", SERVER_PORT)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.connect((SERVER_IP, SERVER_PORT))
            print(f"server connection established, sending message '{message}'")
            server_socket.sendall(bytes(message, 'utf-8'))
            print("message sent to server, waiting for reply")
            while True:
                data = server_socket.recv(1024)
                if not data:
                    break
                print(f"Received server response: '{data!r}' [{len(data)} bytes], forwarding to client")
                client_conn.sendall(data)
                data = client_conn.recv(1024)
                if not data:
                    break
                print(f"Received client message: '{data!r}' [{len(data)} bytes], forwarding to server")
                server_socket.sendall(data)


print("VPN is done!")