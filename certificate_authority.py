#!/usr/bin/env python3

import socket
import arguments
import argparse
import cryptgraphy_simulator
from time import sleep

# Run 'python3 certificate_authority.py --help' to see what these lines do
parser = argparse.ArgumentParser('Starts a server that returns the data sent to it unmodified')
parser.add_argument('--CA_IP', help='IP address at which to host the certificate authority', **arguments.ip_addr_arg)
parser.add_argument('--CA_port', help='Port number at which to host the certificate authority', **arguments.CA_port_arg)
parser.add_argument('--public_key', default=None, type=arguments._public_key, help='Public key for the certificate authority as a tuple')
args = parser.parse_args()

CA_IP = args.CA_IP  # Address to listen on
CA_PORT = args.CA_port  # Port to listen on (non-privileged ports are > 1023)

# Use a random public key if none if provided
if args.public_key == None:
    args.public_key = cryptgraphy_simulator.asymmetric_key_gen()[0]
public_key = args.public_key
private_key = public_key[1] - public_key[0]

print(f"Certificate Authority started using public key '{public_key}' and private key '{private_key}'")

def sign_certificate(certificate):
    return 'D' + cryptgraphy_simulator.public_key_encrypt((private_key, public_key[1]), certificate)[1:]

print("Certificate authority starting - listening for connections at IP", CA_IP, "and port", CA_PORT)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((CA_IP, CA_PORT))
    try:
        while True:
            s.listen()
            conn, addr = s.accept()
            with conn:
                try:
                    print(f"Connected established with {addr}")
                    while True:
                        data = conn.recv(1024)
                        print(f"Received client message: '{data!r}' [{len(data)} bytes]")
                        data = data.decode('utf-8')
                        if data == 'key':
                            print(f"Sending the certificate authority's public key {public_key} to the client")
                            conn.sendall(bytes(str(public_key), 'utf-8'))
                        elif data == 'done':
                            print(f"{addr} has closed the remote connection - listening ")
                            break
                        elif not data:
                            sleep(0.1)
                        elif data[0] != '$':
                            print(f"Received malformed request from client ({data}): sending error message back")
                            error_msg = f"Request '{data}' to the certificate authority was malformed: requests should be 'key' to return the certificate authority's public key or '$<message>' to sign <message>"
                            conn.sendall(bytes(str(error_msg), 'utf-8'))
                        else:
                            # In practice, this process is a lot more involved and requires the server owner to prove
                            # their identity in various ways, but we're skipping that here for simplicity
                            print(f"Signing '{data[1:]}' and returning it to the client.")
                            conn.sendall(bytes(sign_certificate(data[1:]), 'utf-8'))
                except KeyboardInterrupt:
                    break
    except KeyboardInterrupt:
        pass

# This certificate authority will run until given the Keyboard Interrupt (ctrl + c)
print("Certificate authority is done!")