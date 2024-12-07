import random

#### DO NOT CHANGE ANY OF THESE FUNCTIONS! ####

# an attempt at type-safety
def _to_str(x):
    if type(x) == str:
        return x
    if type(x) == bytes:
        return x.decode('utf-8')
    if type(x) == int:
        return str(x)
    try:
        return str(x)
    except ValueError:
        raise AssertionError(f"'{x}' (of type '{type(x)}') cannot be converted to a string")

def _to_int(x):
    if type(x) == int:
        return x
    if type(x) == bytes:
        x = _to_str(x)
    try:
        return int(x)
    except ValueError:
        raise AssertionError(f"'{x}' (of type '{type(x)}') cannot be converted to an int")
    
def _to_public_key(x):
    if type(x) == bytes:
        x = _to_str(x)
    if type(x) == str:
        x = eval(x)
    if type(x) == tuple:
        assert len(x) == 2, f"{x} has the wrong number ({len(x)}) of elements to be a public key: requires 2"
        return (_to_int(x[0]), _to_int(x[1]))

def generate_nonce() -> int:
    return random.randint(1, 99999)

## ASYMMETRIC CRYPTOGRAPHY SIMULATIONS ##

# this is very insecure. can you see why?
def asymmetric_key_gen(p=56533) -> tuple[tuple[int, int], int]:
    p = _to_int(p)
    public_key = (random.randrange(1, p), p)
    private_key = p - public_key[0]
    return (public_key, private_key)

# call this function to encrypt with a public key
def public_key_encrypt(key, message) -> str:
    key = _to_public_key(key); message = _to_str(message)
    return "E_" + str(key) + '[' + message + ']'

# call this function to decrypt with a private key
def private_key_decrypt(key, cyphertext) -> str:
    key = _to_int(key); cyphertext = _to_str(cyphertext)
    if len(cyphertext) < 6 or cyphertext[:3] != 'E_(' or ')[' not in cyphertext or cyphertext[-1] != ']':
        raise AssertionError('"{}" is not formatted as an asymmetric cyphertext'.format(cyphertext))
    # using eval is very bad practice. can you guess why?
    public_key = eval(cyphertext[2:cyphertext.index(')[')+1])
    if type(public_key) != tuple or type(public_key[0]) != int or type(public_key[1]) != int:
        raise AssertionError('"{}" does not have a properly formatted asymmetric key'.format(cyphertext))
    if int(public_key[0])+int(key) != int(public_key[1]):
        raise AssertionError("{} is not a private key matching public key {}".format(key, public_key))
    return cyphertext[cyphertext.index('[')+1:-1]

# use this function with the Certificate Authority's public key to verify certificates signed by the Certificate Authority
# if verification is successful, returns the unsigned certificate
# if verification is unsuccessful, throws an AssertionError exception (catch it with a try/except!)
def verify_certificate(public_key, certificate) -> str:
    public_key = _to_public_key(public_key); certificate = _to_str(certificate)
    try:
        assert certificate[0] == 'D'
        return private_key_decrypt(public_key[0], 'E' + certificate[1:])
    except AssertionError:
        raise AssertionError('Could not verify the authenticity of certificate "{}" with certificate authority public key "{}"'.format(certificate, public_key))
    
## SYMMETRIC CRYPTOGRAPHY SIMULATIONS ##

def generate_symmetric_key() -> int:
    return generate_nonce()

# use this to encrypt with a symmetric key
def symmetric_encrypt(key, message) -> str:
    key = _to_int(key); message = _to_str(message)
    return 'symmetric_' + str(key) + '[' + message + ']'

# use this to decrypt with a symmetric key
def symmetric_decrypt(key, cyphertext) -> str:
    key = _to_int(key); cyphertext = _to_str(cyphertext)
    if len(cyphertext) < 12 or cyphertext[:10] != 'symmetric_' or cyphertext[10] not in '0123456789' or '[' not in cyphertext or cyphertext[-1] != ']':
        raise AssertionError('"{}" is not formatted as an symmetric cyphertext'.format(cyphertext))
    try:
        cyphertext_key = int(cyphertext[10:cyphertext.index('[')])
    except TypeError:
        raise AssertionError('"{}" does not have a properly formatted symmetric key'.format(cyphertext))
    if cyphertext_key != key:
        raise AssertionError("{} is the wrong key for {}".format(cyphertext_key, cyphertext))
    return cyphertext[cyphertext.index('[')+1:-1]

# use this to generate a simulated HMAC
def generate_HMAC(key, message) -> int:
    key = _to_int(key); message = _to_str(message)
    prng = random.Random(str(key) + message)
    return prng.randrange(1, 100000)

## post-handshake TLS ##

# use a symmetric key established by a TLS handshake to encrypt a message and add a HMAC
def tls_encode(key, message) -> str:
    key = _to_int(key); message = _to_str(message)
    message = symmetric_encrypt(key, message)
    HMAC = generate_HMAC(key, message)
    return f"HMAC_{HMAC}[{message}]"

# use a symmetric key established by a TLS handshake to decrypt and authenticate a HMACed and encrypted message
def tls_decode(key, message) -> str:
    key = _to_int(key); message = _to_str(message)
    if len(message) < 7 or message[:5] != 'HMAC_' or message[5] not in '0123456789' or '[' not in message or message[-1] != ']':
        raise AssertionError(f'"{message}" does not have a properly formatted HMAC applied')
    try:
        HMAC = int(message[5:message.index('[')])
    except TypeError:
        raise AssertionError(f'"{message}" does not have a properly formatted HMAC applied')
    message = message[message.index('[')+1:-1]
    if HMAC != generate_HMAC(key, message):
        raise AssertionError(f"Integrity of message {message} could not be authenticated with HMAC {HMAC} and key {key}")
    return symmetric_decrypt(key, message)