import sys
import getpass
from wallet_manager import WalletManager  # Ensure WalletManager is in the same directory or properly installed

def main():
    """
    Main script to create a wallet using the WalletManager class.
    Accepts a passphrase from the user, securely converts it to a bytearray,
    and creates a new wallet.
    """
    try:
        # Prompt user for a passphrase securely and immediately convert to bytearray
        passphrase_bytes = bytearray(getpass.getpass(prompt="Enter a secure passphrase: ").encode())

        # Instantiate WalletManager and create a new wallet
        wallet_manager = WalletManager(passphrase=passphrase_bytes)
        print("Wallet created successfully.")
        print(f"Wallet Address: {wallet_manager.get_public_key(passphrase=passphrase_bytes.decode())}")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Securely clear the passphrase from memory
        for i in range(len(passphrase_bytes)):
            passphrase_bytes[i] = 0

if __name__ == "__main__":
    main()
