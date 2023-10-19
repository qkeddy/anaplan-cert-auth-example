from base64 import b64encode
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import json


# Generate the `encodedData` parameter
def create_encoded_data_string(message_bytes):
    # Step #1 - Convert the binary message into Base64 encoding:
    # When transmitting binary data, especially in text-based protocols like JSON,
    # it's common to encode the data into a format that's safe for transmission.
    # Base64 is a popular encoding scheme that transforms binary data into an ASCII string,
    # making it safe to embed in JSON, XML, or other text-based formats.
    message_bytes_b64e = b64encode(message_bytes)

    # Step #2 - Convert the Base64-encoded binary data to an ASCII string:
    # After Base64 encoding, the result is still in a binary format.
    # By decoding it to ASCII, we get a string representation of the Base64 data,
    # which is easily readable and can be transmitted or stored as regular text.
    message_str_b64e = message_bytes_b64e.decode('ascii')

    return message_str_b64e


# Generate the `encodedSignedData` parameter
def create_signed_encoded_data_string(message_bytes, key_file, passphrase):

    # Step #1 - Open the private key file for reading:
    # Private keys are sensitive pieces of data that should be stored securely.
    # Here, we're reading the private key file from the disk using Python's file I/O functions.
    key_file_content = open(key_file, 'r', encoding='utf-8').read()

    # Step #2 - Import the RSA private key:
    # The RSA private key is imported from the previously read file content.
    # If the key is encrypted, a passphrase will be required to decrypt and access the key.
    my_key = RSA.import_key(key_file_content, passphrase=passphrase)

    # Step #3 - Prepare the RSA key for signing operations:
    # Before we can use the RSA key to sign data, we need to prepare it using
    # the PKCS#1 v1.5 standard, a common standard for RSA encryption and signatures.
    signer = pkcs1_15.new(my_key)

    # Step #4 - Create a SHA-512 hash of the message bytes:
    # It's common practice to create a cryptographic hash of the data you want to sign
    # instead of signing the data directly. This ensures the integrity of the data.
    # Here, we're using the SHA-512 algorithm, which produces a fixed-size 512-bit (64-byte) hash.
    message_hash = SHA512.new(message_bytes)

    # Step #5 - Sign the hashed message:
    # Once the data is hashed, the hash is then signed using the private key.
    # This produces a signature that can be verified by others using the associated public key.
    message_hash_signed = signer.sign(message_hash)

    # Step #6 - Encode the binary signature to Base64 and decode it to an ASCII string:
    # Similar to our earlier function, after signing, the signature is in a binary format.
    # We convert this to Base64 for safe transmission or storage, and then decode it to a string.
    message_str_signed_b64e = b64encode(message_hash_signed).decode('utf-8')

    return message_str_signed_b64e


def create_json_body(encoded_data_value, signed_encoded_data_value):
    data = {
        "encodedData": encoded_data_value,
        "encodedSignedData": signed_encoded_data_value
    }
    return json.dumps(data, indent=4)


# create random 100 byte message
message_bytes = get_random_bytes(100)

# Provide path to the private key in the PEM format
private_key_file = './quin_eddy_private-key.pem'

# Provide the private key passphrase. If there is no passphrase, please insert `None`
private_key_file_passphrase = "fltbsl0294"

# Create the encoded data string
message_str_b64e = create_encoded_data_string(message_bytes=message_bytes)

# Create an encoded signed data string
message_str_signed_b64e = create_signed_encoded_data_string(
    message_bytes=message_bytes, key_file=private_key_file, passphrase=private_key_file_passphrase)

# Get the formatted body for the Anaplan API token authentication endpoint (https://auth.anaplan.com/token/authenticate) to generate an `access_token`
certificate_api_body = create_json_body(
    encoded_data_value=message_str_b64e, signed_encoded_data_value=message_str_signed_b64e)

print(certificate_api_body)
