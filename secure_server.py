#!/usr/bin/env python3

import socket
import arguments
import argparse
import cryptgraphy_simulator

# Run 'python3 secure_echo_server.py --help' to see what these lines do
parser = argparse.ArgumentParser('Starts a server that returns the data sent to it unmodified')
parser.add_argument('--server_IP', help='IP address at which to host the server', **arguments.ip_addr_arg)
parser.add_argument('--server_port', help='Port number at which to host the server', **arguments.server_port_arg)
parser.add_argument('--CA_IP', help='IP address at which the certificate authority is hosted', **arguments.ip_addr_arg)
parser.add_argument('--CA_port', help='Port number at which the certificate authority is hosted', **arguments.CA_port_arg)
args = parser.parse_args()

SERVER_IP = args.server_IP  # Address to listen on
SERVER_PORT = args.server_port  # Port to listen on (non-privileged ports are > 1023)

### Instructions ###
# In order to execute TLS with a client, a server needs to do the
# following once, before accepting incoming connections:
#  * Generate a public/private key pair (done below)
#  * Create a certificate that contains the server's IP address, port, and public key
#    * Fill in format_certificate() below
#  * Verify its identity with the certificate authority (we'll skip this step)
#  * Send the certificate to the certificate authority to be signed
#  * Save the signed certificate to send to incoming clients as part of the TLS handshake

# Create certificate: server IP address, port, public key
def format_certificate(public_key):
    unsigned_certificate = f"{SERVER_IP}, {SERVER_PORT}, {public_key[0]}, {public_key[1]}"
    print(f"Prepared the formatted unsigned certificate '{unsigned_certificate}'")
    return unsigned_certificate

# Generate a public/private key pair
public_key, private_key = cryptgraphy_simulator.asymmetric_key_gen()
print(f"Generated public key '{public_key}' and private key '{private_key}'")

# Get the socket address of the certificate authority from the command line
CA_IP = args.CA_IP # the IP address used by the certificate authority
CA_PORT = args.CA_port # the port used by the certificate authority

# Connect to the certificate authority 
print(f"Connecting to the certificate authority at IP {CA_IP} and port {CA_PORT}")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((CA_IP, CA_PORT))
    unsigned_certificate = format_certificate(public_key)
    print(f"Connection established, sending certificate '{unsigned_certificate}' to the certificate authority to be signed")
    # The certificate authority is programmed to recognize messages following a '$'
    # as certificates in need of signing
    s.sendall(bytes('$' + unsigned_certificate, 'utf-8'))
    signed_certificate = s.recv(1024).decode('utf-8')
    # close the connection with the certificate authority
    s.sendall(bytes('done', 'utf-8'))

print(f"Received signed certificate '{signed_certificate}' from the certificate authority")

def TLS_handshake_server(connection):
    # Step 1: send a signed cert to client 
    connection.sendall(bytes(signed_certificate, 'utf-8'))
    print(f"Sent signed certificate to client: {signed_certificate}")
    
    # Step 2: Receive an encrypted symmetric key from the client
    encrypted_key = connection.recv(1024).decode('utf-8')
    print(f"Received encrypted symmetric key: {encrypted_key}")

    # Step 3: Decrypt the symmetric key using the server's private key
    decryped_key = cryptgraphy_simulator.private_key_decrypt(private_key, encrypted_key)
    print(f"Decrypted symmetric key: {decryped_key}")
    return decryped_key

def process_message(message):
    return message + str(len(message))

print("server starting - listening for connections at IP", SERVER_IP, "and port", SERVER_PORT)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((SERVER_IP, SERVER_PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected established with {addr}")
        symmetric_key = TLS_handshake_server(conn)
        print(f"TLS handshake complete: established symmetric key '{symmetric_key}', acknowledging to client")
        conn.sendall(bytes(cryptgraphy_simulator.symmetric_encrypt(symmetric_key, f"Symmetric key '{symmetric_key}' received"), 'utf-8'))
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"Received client message: '{data!r}' [{len(data)} bytes]")
            message = cryptgraphy_simulator.tls_decode(symmetric_key, data.decode('utf-8'))
            print(f"Decoded message '{message}' from client")
            response = process_message(message)
            print(f"Responding '{response}' to the client")
            encoded_response = cryptgraphy_simulator.tls_encode(symmetric_key, response)
            print(f"Sending encoded response '{encoded_response}' back to the client")
            conn.sendall(bytes(encoded_response, 'utf-8'))

print("server is done!")