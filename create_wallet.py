import os
import sys
from web3 import Web3
import gnupg
import io

# Initialize GPG
gpg = gnupg.GPG()

# Function to create a new Web3 wallet
def create_wallet():
    wallet = Web3().eth.account.create()
    return wallet.address, wallet.key.hex()

# Function to encrypt .env content and save it as .env.gpg
def encrypt_env_with_gpg(address, private_key, passphrase, encrypted_file=".env.gpg"):
    # Prepare .env content
    env_content = f"WALLET_ADDRESS={address}\nPRIVATE_KEY={private_key}"
    env_stream = io.BytesIO(env_content.encode())

    # Encrypt the content and save it to a file
    encrypted_data = gpg.encrypt_file(
        env_stream,
        recipients=None,  # Symmetric encryption
        output=encrypted_file,
        passphrase=passphrase,
        symmetric=True
    )

    if encrypted_data.ok:
        print(f".env content encrypted and saved to {encrypted_file}")
    else:
        print(f"Failed to encrypt the .env content: {encrypted_data.status}")

# Main script logic
if __name__ == "__main__":
    # Check if a passphrase was provided
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <passphrase>")
        sys.exit(1)

    # Get the passphrase from the command-line argument
    passphrase = sys.argv[1]

    # Step 1: Create a new wallet
    wallet_address, wallet_private_key = create_wallet()
    print(f"New Wallet Address: {wallet_address}")
    print(f"New Wallet Private Key: {wallet_private_key}")

    # Step 2: Encrypt and save the wallet details
    encrypt_env_with_gpg(wallet_address, wallet_private_key, passphrase)
