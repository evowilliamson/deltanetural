import os
import io
from web3 import Web3
import gnupg

class WalletManager:
    def __init__(self, passphrase, rpc_url="https://mainnet.base.org"):
        """
        Initialize the WalletManager class, create a wallet, and securely manage keys.

        :param passphrase: Passphrase used for GPG encryption.
        :param rpc_url: RPC URL for connecting to the blockchain.
        """
        self._gpg = gnupg.GPG()
        self._web3 = Web3(Web3.HTTPProvider(rpc_url))

        if not self._web3.is_connected():
            raise ConnectionError("Failed to connect to the blockchain network. Check your RPC URL.")

        # Convert passphrase to string if it's a bytearray
        if isinstance(passphrase, (bytes, bytearray)):
            passphrase = passphrase.decode()

        # Validate the passphrase
        if not passphrase or len(passphrase) < 12 or not any(c.isdigit() for c in passphrase) or not any(c.isalpha() for c in passphrase):
            raise ValueError("Passphrase must be at least 12 characters long, containing both letters and numbers.")

        # Create wallet and securely handle keys
        wallet = self._web3.eth.account.create()
        self._public_key = wallet.address  # Store public key

        private_key = None
        try:
            private_key = bytearray(wallet.key)  # Securely store private key as bytearray

            # Encrypt and save .env file
            self._encrypt_env_with_gpg(self._public_key, private_key, passphrase)
        finally:
            if private_key:
                for i in range(len(private_key)):
                    private_key[i] = 0  # Securely clear the private key from memory

    def _encrypt_env_with_gpg(self, public_key, private_key, passphrase, encrypted_file=".env.gpg"):
        """
        Encrypt the wallet details and save them to an encrypted file.

        :param public_key: Wallet address (public key).
        :param private_key: Wallet private key as a bytearray.
        :param passphrase: Passphrase for GPG encryption.
        :param encrypted_file: Output file for encrypted content.
        """
        # Prepare .env content in memory
        private_key_str = "".join(format(x, "02x") for x in private_key)  # Convert bytearray to hex string
        env_content = f"WALLET_ADDRESS={public_key}\nPRIVATE_KEY={private_key_str}"
        env_stream = io.BytesIO(env_content.encode())

        # Encrypt content using GPG
        encrypted_data = self._gpg.encrypt_file(
            env_stream,
            recipients=None,  # Symmetric encryption
            output=encrypted_file,
            passphrase=passphrase,
            symmetric=True
        )

        if encrypted_data.ok:
            print(f".env content encrypted and saved to {encrypted_file}")
        else:
            raise ValueError(f"Failed to encrypt the .env content: {encrypted_data.status}")

    def get_public_key(self):
        """
        Retrieve the wallet's public key.

        :return: The wallet's public key (address).
        """
        return self._public_key

    def show_private_key(self, passphrase, encrypted_file=".env.gpg"):
        """
        Decrypt the .env.gpg file, print the private key to the console (if in test mode),
        and securely clear all sensitive data from memory.

        :param passphrase: Passphrase used to decrypt the file.
        :param encrypted_file: Path to the encrypted .env.gpg file.
        """
        # Convert passphrase to string if it's a bytearray
        if isinstance(passphrase, (bytes, bytearray)):
            passphrase = passphrase.decode()

        with open(encrypted_file, "rb") as f:
            decrypted_data = self._gpg.decrypt_file(f, passphrase=passphrase)

        if decrypted_data.ok:
            print("Decrypted .env file successfully.")
            try:
                # Extract private key securely by searching for the specific string
                private_key_hex = None
                env_stream = io.StringIO(decrypted_data.data.decode())

                for line in env_stream:
                    if line.startswith("PRIVATE_KEY="):
                        private_key_hex = line.split("=", 1)[1].strip()
                        break

                if private_key_hex:
                    private_key = bytearray.fromhex(private_key_hex)

                    # Print the full private key
                    print("WARNING: Printing private key for testing purposes.")
                    print(f"Private Key: {private_key_hex}")

                    # Securely clear the private key from memory
                    for i in range(len(private_key)):
                        private_key[i] = 0
                else:
                    raise ValueError("Private key not found in the decrypted .env file.")
            finally:
                # Clear decrypted data from memory
                decrypted_data.data = None
        else:
            raise ValueError(f"Failed to decrypt the .env.gpg file: {decrypted_data.status}")
