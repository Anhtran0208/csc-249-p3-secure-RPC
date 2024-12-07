#!/usr/bin/env python3

import socket
import arguments
import argparse
import cryptgraphy_simulator

# Run 'python3 secure_client.py --help' to see what these lines do
parser = argparse.ArgumentParser('Send a message to a server at the given address and print the response')
parser.add_argument('--server_IP', help='IP address at which the server is hosted', **arguments.ip_addr_arg)
parser.add_argument('--server_port', help='Port number at which the server is hosted', **arguments.server_port_arg)
parser.add_argument('--VPN_IP', help='IP address at which the VPN is hosted', **arguments.ip_addr_arg)
parser.add_argument('--VPN_port', help='Port number at which the VPN is hosted', **arguments.vpn_port_arg)
parser.add_argument('--CA_IP', help='IP address at which the certificate authority is hosted', **arguments.ip_addr_arg)
parser.add_argument('--CA_port', help='Port number at which the certificate authority is hosted', **arguments.CA_port_arg)
parser.add_argument('--CA_public_key', default=None, type=arguments._public_key, help='Public key for the certificate authority as a tuple')
parser.add_argument('--message', default=['Hello, world'], nargs='+', help='The message to send to the server', metavar='MESSAGE')
args = parser.parse_args()

SERVER_IP = args.server_IP  # The server's IP address
SERVER_PORT = args.server_port  # The port used by the server
VPN_IP = args.VPN_IP  # The server's IP address
VPN_PORT = args.VPN_port  # The port used by the server
CA_IP = args.CA_IP # the IP address used by the certificate authority
CA_PORT = args.CA_port # the port used by the certificate authority
MSG = ' '.join(args.message) # The message to send to the server

if not args.CA_public_key:
    # If the certificate authority's public key isn't provided on the command line,
    # fetch it from the certificate authority directly
    # This is bad practice on the internet. Can you see why?
    print(f"Connecting to the certificate authority at IP {CA_IP} and port {CA_PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((CA_IP, CA_PORT))
        print("Connection established, requesting public key")
        s.sendall(bytes('key', 'utf-8'))
        CA_public_key = s.recv(1024).decode('utf-8')
        # close the connection with the certificate authority
        s.sendall(bytes('done', 'utf-8'))
    print(f"Received public key {CA_public_key} from the certificate authority for verifying certificates")
    CA_public_key = eval(CA_public_key)
else:
    CA_public_key = eval(args.CA_public_key)

# Add an application-layer header to the message that the VPN can use to forward it
def encode_message(message):
    message = str(SERVER_IP) + '~IP~' +str(SERVER_PORT) + '~port~' + message
    return message

def TLS_handshake_client(connection, server_ip=SERVER_IP, server_port=SERVER_PORT):
    print("Requesting handshake...")
    # step 1: receive signed cert from the server
    signed_certificate = connection.recv(1024).decode('utf-8')
    
    # step 2: verify the certificate with cert authority's public key
    verified_cert = cryptgraphy_simulator.verify_certificate(CA_public_key, signed_certificate)
    print("Verified cert", verified_cert)
    
    # step 3: extract server's public key, ip address, port
    extracted_ip, extracted_port, public_key_1, public_key_2 = verified_cert.split(',')
    
    # convert to the expected type
    extracted_ip, extracted_port = str(extracted_ip), int(extracted_port)
    server_public_key = (int(public_key_1), int(public_key_2))

    # Step 4: Verify server IP and port match the certificate
    if extracted_ip != server_ip or extracted_port != server_port:
        raise ValueError("Server IP/Port mismatch in certificate")

    # Step 5: Generate a symmetric key
    symm_key = cryptgraphy_simulator.generate_symmetric_key()
    print(f"Generated symmetric key: {symm_key}")

    # Step 6: Encrypt the symmetric key 
    encrypted_symm_key = cryptgraphy_simulator.public_key_encrypt(server_public_key, symm_key)
    print(f"Encrypted symmetric key: {encrypted_symm_key}")

    # Step 7: Send the encrypted symmetric key to the server
    connection.sendall(bytes(encrypted_symm_key, 'utf-8'))
    print("Encrypted symmetric key sent.")

    # Return the symmetric key
    return symm_key

print("Client starting - connecting to VPN at IP", VPN_IP, "and port", VPN_PORT)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((VPN_IP, VPN_PORT))
    symmetric_key = TLS_handshake_client(s)
    print(f"TLS handshake complete: sent symmetric key '{symmetric_key}', waiting for acknowledgement")
    data = s.recv(1024).decode('utf-8')
    print(f"Received acknowledgement '{cryptgraphy_simulator.symmetric_decrypt(symmetric_key, data)}', preparing to send message")
    MSG = cryptgraphy_simulator.tls_encode(symmetric_key,MSG)
    print(f"Sending message '{MSG}' to the server")
    s.sendall(bytes(MSG, 'utf-8'))
    print("Message sent, waiting for reply")
    data = s.recv(1024)

print(f"Received raw response: '{data}' [{len(data)} bytes]")
print(f"Decoded message '{cryptgraphy_simulator.tls_decode(symmetric_key, data.decode('utf-8'))}' from server")
print("client is done!")