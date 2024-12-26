import sys
import gnupg
from web3 import Web3
import io

# Initialize GPG
gpg = gnupg.GPG()

# Connect to the Ethereum network (e.g., Mainnet or Base L2)
ETH_RPC_URL = "https://mainnet.base.org"  # Replace with the desired Ethereum-compatible RPC endpoint
web3 = Web3(Web3.HTTPProvider(ETH_RPC_URL))

# Verify connection to the Ethereum network
if not web3.is_connected():
    print("Failed to connect to the Ethereum network. Check your RPC URL.")
    sys.exit(1)

# Function to decrypt the .env.gpg file and retrieve its content
def decrypt_env_file(encrypted_file=".env.gpg", passphrase=""):
    with open(encrypted_file, "rb") as f:
        decrypted_data = gpg.decrypt_file(f, passphrase=passphrase)

    if decrypted_data.ok:
        # Parse the decrypted content
        env_stream = io.StringIO(decrypted_data.data.decode())
        env_variables = {}
        for line in env_stream:
            key, value = line.strip().split("=")
            env_variables[key] = value
        return env_variables
    else:
        print(f"Failed to decrypt the .env.gpg file: {decrypted_data.status}")
        sys.exit(1)

# Function to send ETH to another address
def send_eth(sender_private_key, recipient_address, amount_eth):
    # Validate recipient address
    if not Web3.is_address(recipient_address):
        print(f"Invalid recipient address: {recipient_address}")
        sys.exit(1)

    # Convert ETH amount to Wei
    amount_wei = Web3.to_wei(amount_eth, "ether")

    # Get the sender's address from the private key
    sender_address = web3.eth.account.from_key(sender_private_key).address

    # Get the current nonce for the sender's address
    nonce = web3.eth.get_transaction_count(sender_address)

    # Build the transaction
    transaction = {
        "to": recipient_address,
        "value": amount_wei,
        "gas": 21000,  # Gas limit for a simple ETH transfer
        "gasPrice": web3.eth.gas_price,  # Current gas price from the network
        "nonce": nonce,
        "chainId": web3.eth.chain_id,  # Get the network's chain ID
    }

    # Sign the transaction
    signed_txn = web3.eth.account.sign_transaction(transaction, private_key=sender_private_key)

    # Send the signed transaction
    tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
    print(f"Transaction sent! TX Hash: {tx_hash.hex()}")
    return tx_hash.hex()

# Main script logic
if __name__ == "__main__":
    # Check if all required arguments are provided
    if len(sys.argv) != 4:
        print("Usage: python script_name.py <recipient_address> <amount_eth> <passphrase>")
        sys.exit(1)

    recipient_address = sys.argv[1]
    amount_eth = float(sys.argv[2])  # Convert ETH amount to float
    passphrase = sys.argv[3]  # Get passphrase from the command-line argument

    # Step 1: Decrypt the .env.gpg file
    env_variables = decrypt_env_file(passphrase=passphrase)

    # Step 2: Retrieve the private key from the decrypted .env
    sender_private_key = env_variables.get("PRIVATE_KEY")
    if not sender_private_key:
        print("PRIVATE_KEY not found in the .env file.")
        sys.exit(1)

    # Step 3: Send ETH
    try:
        tx_hash = send_eth(sender_private_key, recipient_address, amount_eth)
        print(f"Transaction successful! TX Hash: {tx_hash}")
    except Exception as e:
        print(f"An error occurred: {e}")
