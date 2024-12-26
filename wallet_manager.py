import os
import io
from web3 import Web3
import gnupg

class WalletManager:
    def __init__(self, passphrase=None, rpc_url="https://mainnet.base.org"):
        """
        Initialize the WalletManager class, create a wallet, and securely manage keys.

        :param passphrase: Passphrase used for GPG encryption.
        :param rpc_url: RPC URL for connecting to the blockchain.
        """
        self._gpg = gnupg.GPG()
        self._web3 = Web3(Web3.HTTPProvider(rpc_url))

        if passphrase == None:
            return

        if not self._web3.is_connected():
            raise ConnectionError("Failed to connect to the blockchain network. Check your RPC URL.")

        # Convert passphrase to string if it's a bytearray
        if isinstance(passphrase, (bytes, bytearray)):
            passphrase = passphrase.decode()

        # Create wallet and securely handle keys
        wallet = self._web3.eth.account.create()
        private_key = None
        try:
            private_key = bytearray(wallet.key)  # Securely store private key as bytearray

            # Encrypt and save .env file
            self._encrypt_env_with_gpg(wallet.address, private_key, passphrase)
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

    def get_public_key(self, passphrase):
        """
        Retrieve the wallet's public key.

        :return: The wallet's public key (address).
        """
        return self.get_key(passphrase=passphrase, key="WALLET_ADDRESS")

    def get_private_key(self, passphrase):
        """
        Retrieve the wallet's private key.

        :return: The wallet's private key (address).
        """
        return self.get_key(passphrase=passphrase, key="PRIVATE_KEY")

    def _get_decrypted_data(self, passphrase, encrypted_file=".env.gpg"):
        """
        Get the decrypted data from the .env.gpg file

        :param passphrase: Passphrase used to decrypt the file.
        :param encrypted_file: Path to the encrypted .env.gpg file.
        """

        with open(encrypted_file, "rb") as f:
            decrypted_data = self._gpg.decrypt_file(f, passphrase=passphrase)

        return decrypted_data

    def _extract_value(self, data, key):
        """
        Extract the value associated with a given key from the data string.

        :param data: The input data string containing key-value pairs.
        :param key: The key whose value needs to be extracted.
        :return: The extracted value or None if the key is not found.
        """
        prefix = f"{key}="
        start_index = data.find(prefix)

        if start_index != -1:
            # Extract the value after the "key=" prefix and split at newline to get the value
            value = data[start_index + len(prefix):].split("\n")[0].strip()
            return value
        else:
            raise Exception(f"{key} not found")

        return None

    def get_key(self, passphrase, key):
        """
        Get the private key
        :param passphrase: Passphrase used to decrypt the file.
        :param encrypted_file: Path to the encrypted .env.gpg file.
        """

        decrypted_data = self._get_decrypted_data(passphrase=passphrase)
        return self._extract_value(decrypted_data.data.decode(), key)

    def show_private_key(self, passphrase, encrypted_file=".env.gpg"):
        """
        Decrypt the .env.gpg file, print the private key to the console.

        :param passphrase: Passphrase used to decrypt the file.
        :param encrypted_file: Path to the encrypted .env.gpg file.
        """

        print(f"Private Key: {self.get_private_key(passphrase=passphrase)}")
        
