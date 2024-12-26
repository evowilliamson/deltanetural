import sys
import os
import gnupg
from web3 import Web3
import io

# Initialize GPG
gpg = gnupg.GPG()

# Connect to the Base network
BASE_RPC_URL = "https://mainnet.base.org"  # Official Base network RPC endpoint
web3 = Web3(Web3.HTTPProvider(BASE_RPC_URL))

# Verify connection to the Base network
if not web3.is_connected():
    print("Failed to connect to Base network. Check your RPC URL.")
    sys.exit(1)

# Function to decrypt the .env.gpg file and load environment variables
def decrypt_env_file(encrypted_file=".env.gpg", passphrase=""):
    with open(encrypted_file, "rb") as f:
        decrypted_data = gpg.decrypt_file(f, passphrase=passphrase)

    if decrypted_data.ok:
        print("Decrypted .env file successfully.")
        # Load environment variables from the decrypted content
        env_stream = io.StringIO(decrypted_data.data.decode())
        env_variables = {}
        for line in env_stream:
            key, value = line.strip().split("=")
            env_variables[key] = value
        return env_variables
    else:
        print(f"Failed to decrypt the .env.gpg file: {decrypted_data.status}")
        sys.exit(1)

# Function to get the ETH balance of a wallet
def get_eth_balance(wallet_address):
    balance_wei = web3.eth.get_balance(wallet_address)  # Get balance in Wei
    balance_eth = Web3.from_wei(balance_wei, "ether")    # Convert to ETH
    return balance_eth

# Main script logic
if __name__ == "__main__":
    # Check if a passphrase was provided
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <passphrase>")
        sys.exit(1)

    passphrase = sys.argv[1]  # Get passphrase from the command-line argument

    # Step 1: Decrypt the .env.gpg file
    env_variables = decrypt_env_file(passphrase=passphrase)

    # Step 2: Retrieve the public key (WALLET_ADDRESS) from the decrypted .env
    wallet_address = env_variables.get("WALLET_ADDRESS")
    if not wallet_address:
        print("WALLET_ADDRESS not found in the decrypted .env file.")
        sys.exit(1)

    # Step 3: Validate the wallet address
    if not Web3.is_address(wallet_address):
        print(f"Invalid wallet address: {wallet_address}")
        sys.exit(1)

    # Step 4: Get the ETH balance of the wallet
    balance_eth = get_eth_balance(wallet_address)
    print(f"Wallet Address: {wallet_address}")
    print(f"ETH Balance on Base Network: {balance_eth} ETH")
