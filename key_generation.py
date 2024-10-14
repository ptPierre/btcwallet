import os
import hashlib
import hmac
import binascii
from hashlib import pbkdf2_hmac
import ecdsa
from bit import PrivateKeyTestnet

# Constants
HARDENED_OFFSET = 0x80000000  # Hardened key offset (2^31)

# Step 1: Generate a random 128-bit (16-byte) string (entropy)
def generate_random_entropy():
    return os.urandom(16)

# Step 2: Calculate the SHA-256 hash and extract the first 4 bits (checksum)
def get_checksum(entropy):
    hash_digest = hashlib.sha256(entropy).hexdigest()
    first_byte = int(hash_digest[:2], 16)  # Convert the first two hex characters to an integer (first byte)
    return format(first_byte, '08b')[:4]  # Get the first 4 bits

# Step 3: Append the checksum to the entropy and convert to binary
def entropy_with_checksum(entropy):
    checksum = get_checksum(entropy)
    entropy_bits = ''.join(format(byte, '08b') for byte in entropy)
    return entropy_bits + checksum

# Step 4: Split the binary string into 11-bit sections
def split_into_parts(binary_string):
    return [binary_string[i:i+11] for i in range(0, len(binary_string), 11)]

# Step 5: Convert binary parts to words using the BIP-39 wordlist
def convert_parts_to_words(parts):
    words = []
    with open('word_list.txt', 'r') as file:
        dictionary = file.read().splitlines()
    
    for part in parts:
        number = int(part, 2)  # Convert binary part to integer
        words.append(dictionary[number])
    
    return words

# Step 6: Convert the mnemonic phrase to a seed using PBKDF2-HMAC-SHA512
def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    salt = "mnemonic" + passphrase
    
    # Use PBKDF2-HMAC-SHA512 to derive the seed
    seed = pbkdf2_hmac(
        'sha512',                        
        mnemonic.encode('utf-8'),        
        salt.encode('utf-8'),            
        2048,                            
        64                               
    )
    
    # Return the seed as a byte array
    return seed

# Step 7: Derive the Master Private Key and Chain Code from the seed
def derive_master_key_and_chain_code(seed: bytes) -> (str, str):
    hmac_key = b"Bitcoin seed"  # Key for HMAC-SHA512
    hmac_result = hmac.new(hmac_key, seed, hashlib.sha512).digest()  # HMAC-SHA512
    
    # Split the HMAC result into 32-byte parts
    master_private_key = hmac_result[:32]  # First 32 bytes
    master_chain_code = hmac_result[32:]   # Last 32 bytes
    
    # Return both as hex strings
    return binascii.hexlify(master_private_key).decode(), binascii.hexlify(master_chain_code).decode()

# Step 8: Derive the Master Public Key from the Master Private Key
def derive_master_public_key(master_private_key: str) -> str:
    private_key_bytes = binascii.unhexlify(master_private_key)  # Convert the hex private key to bytes
    
    # Use the secp256k1 curve to generate the public key
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key  # Get the corresponding public key
    
    # The public key is a point on the elliptic curve, we encode it as compressed form
    public_key_bytes = vk.to_string("compressed")  # Compressed public key (33 bytes)
    
    return binascii.hexlify(public_key_bytes).decode()

# Step 9: Derive a Child Key (Non-Hardened or Hardened) from a Parent Key
def derive_child_key(parent_private_key: str, parent_chain_code: str, index: int, hardened=False) -> (str, str):
    if hardened:
        index += HARDENED_OFFSET  # Hardened key derivation
    
    index_bytes = index.to_bytes(4, 'big')  # 4-byte index
    parent_private_key_bytes = binascii.unhexlify(parent_private_key)
    parent_chain_code_bytes = binascii.unhexlify(parent_chain_code)
    
    if hardened:
        # For hardened keys, use 0x00 + parent_private_key + index
        data = b'\x00' + parent_private_key_bytes + index_bytes
    else:
        # For non-hardened keys, use parent_public_key + index
        parent_public_key = derive_master_public_key(parent_private_key)  # Public key from private key
        data = binascii.unhexlify(parent_public_key) + index_bytes

    # HMAC-SHA512 using the parent chain code
    hmac_result = hmac.new(parent_chain_code_bytes, data, hashlib.sha512).digest()

    # First 32 bytes of HMAC result is the tweak value for the new private key
    tweak = int.from_bytes(hmac_result[:32], 'big')
    
    # Calculate the child private key: (parent_private_key + tweak) % curve_order
    parent_private_int = int.from_bytes(parent_private_key_bytes, 'big')
    curve_order = ecdsa.SECP256k1.order  # Curve order for secp256k1
    
    child_private_int = (parent_private_int + tweak) % curve_order
    child_private_key = child_private_int.to_bytes(32, 'big')

    # Child chain code is the second 32 bytes of the HMAC result
    child_chain_code = hmac_result[32:]
    
    return binascii.hexlify(child_private_key).decode(), binascii.hexlify(child_chain_code).decode()

# Step 10: Derive a Child Key at a Specific Index N with Derivation Level M
def derive_child_key_at_index(parent_private_key: str, parent_chain_code: str, index: int, derivation_level: int):
    private_key = parent_private_key
    chain_code = parent_chain_code
    
    for i in range(derivation_level):
        private_key, chain_code = derive_child_key(private_key, chain_code, index)
    
    return private_key, chain_code



# Here i use the functionality from the lib bit to generate a testnet address -> not part of the TD anymore
def private_key_to_testnet_address(private_key_hex: str) -> str:
    key = PrivateKeyTestnet.from_hex(private_key_hex)
    return key.address

def get_testnet_balance(private_key_hex: str) -> float:
    key = PrivateKeyTestnet.from_hex(private_key_hex)
    balance = key.get_balance('btc')
    return float(balance)

def send_testnet_transaction(private_key_hex: str, to_address: str, amount: float):
    key = PrivateKeyTestnet.from_hex(private_key_hex)
    tx_hash = key.send([(to_address, amount, 'btc')])
    return tx_hash
