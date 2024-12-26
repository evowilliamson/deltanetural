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

    def __init__(self, rpc_url="https://mainnet.base.org"):
        """
        Initialize the WalletManager class, create a wallet, and securely manage keys.

        :param passphrase: Passphrase used for GPG encryption.
        :param rpc_url: RPC URL for connecting to the blockchain.
        """
        self._gpg = gnupg.GPG()
        self._web3 = Web3(Web3.HTTPProvider(rpc_url))

    def _encrypt_env_with_gpg(self, public_key, private_key, passphrase, encrypted_file=".env.gpg"):
        """
        Encrypt the wallet details and save them to an encrypted file.

        :param public_key: Wallet address (public key).
        :param private_key: Wallet private key as a bytearray.
        :param passphrase: Passphrase for GPG encryption.
        :param encrypted_file: Output file for encrypted content.
        """
        # Encrypt content using GPG directly from formatted string
        encrypted_data = self._gpg.encrypt(
            f"WALLET_ADDRESS={public_key}\nPRIVATE_KEY={''.join(format(x, '02x') for x in private_key)}",
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
        Decrypt the .env.gpg file, print the private key to the console.

        :param passphrase: Passphrase used to decrypt the file.
        :param encrypted_file: Path to the encrypted .env.gpg file.
        """

        with open(encrypted_file, "rb") as f:
            decrypted_data = self._gpg.decrypt_file(f, passphrase=passphrase)

        # Search for "PRIVATE_KEY=" directly in the string
        prefix = "PRIVATE_KEY="
        start_index = decrypted_data.data.decode().find(prefix)

        if start_index != -1:
            print(f"Private Key: {decrypted_data.data.decode()[start_index + len(prefix):].strip()}")
        else:
            print("Private key not found.")

