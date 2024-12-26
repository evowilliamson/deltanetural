import getpass
from wallet_manager import WalletManager  # Assuming the WalletManager class is in wallet_manager.py

def main():
    try:
        # Instantiate WalletManager
        wallet_manager = WalletManager()

        # Call show_private_key method to retrieve the private key
        wallet_manager.show_private_key(getpass.getpass("Enter your wallet passphrase: "))

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # Ensure sensitive data is cleared from memory
        passphrase = None

if __name__ == "__main__":
    main()
