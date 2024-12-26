import sys
import gnupg
import io

# Initialize GPG
gpg = gnupg.GPG()

# Function to decrypt the .env.gpg file and retrieve its content
def decrypt_env_file(encrypted_file=".env.gpg", passphrase=""):
    with open(encrypted_file, "rb") as f:
        decrypted_data = gpg.decrypt_file(f, passphrase=passphrase)

    if decrypted_data.ok:
        print("Decrypted .env file successfully.")
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

# Main script logic
if __name__ == "__main__":
    # Check if a passphrase was provided
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <passphrase>")
        sys.exit(1)

    passphrase = sys.argv[1]  # Get passphrase from the command-line argument

    # Step 1: Decrypt the .env.gpg file
    env_variables = decrypt_env_file(passphrase=passphrase)

    # Step 2: Retrieve and display the public and private keys
    public_key = env_variables.get("WALLET_ADDRESS")
    private_key = env_variables.get("PRIVATE_KEY")

    print("Decrypted Keys:")
    if public_key:
        print(f"Public Key (WALLET_ADDRESS): {public_key}")
    else:
        print("Public Key not found in the .env file.")

    if private_key:
        print(f"Private Key (PRIVATE_KEY): {private_key}")
    else:
        print("Private Key not found in the .env file.")
