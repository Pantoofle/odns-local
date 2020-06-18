from typing import Union

from coincurve import PrivateKey, PublicKey
from ecies.utils import generate_key, hex2prv, hex2pub, encapsulate, decapsulate, aes_encrypt, aes_decrypt


class ODNSCypher():
    """
        Holding all cryptography algorithms to encrypt and decrypt queries and
        answers.
    """

    def __init__(self):
        pass

    def encrypt_query(self, query: bytes, server_pk: Union[str, bytes]):
        """
            Encrypt the query to send to the server

            query     - The query
            server_pk - The public key of the server
        """
        # Generate the ephemeral key
        ephemeral_key = generate_key()

        # Parse the server key
        if isinstance(server_pk, str):
            server_pubkey = hex2pub(server_pk)
        elif isinstance(server_pk, bytes):
            server_pubkey = PublicKey(server_pk)
        else:
            raise TypeError("Invalid public key type")

        # Generate the symetric key
        aes_key = encapsulate(ephemeral_key, server_pubkey)
        # Encrypt the query (this adds the nonce)
        cipher_text = aes_encrypt(aes_key, query)
        # Return the message and the symetric key
        return ephemeral_key.public_key.format(False) + cipher_text, aes_key

    def decrypt_query(self, query: bytes, server_sk: Union[str, bytes]):
        """
            Decrypts a query received by the server

            query - The query to decrypt
            server_sk - The server private key
        """
        # Parse the server key
        if isinstance(server_sk, str):
            private_key = hex2prv(server_sk)
        elif isinstance(server_sk, bytes):
            private_key = PrivateKey(server_sk)
        else:
            raise TypeError("Invalid secret key type")

        # Parsre the msg, extract the pubkey and the {IV || payload} from the query
        pubkey = query[0:65]  # uncompressed pubkey's length is 65 bytes
        encrypted = query[65:]
        ephemeral_public_key = PublicKey(pubkey)

        # Generate the AES key
        aes_key = decapsulate(ephemeral_public_key, private_key)
        return aes_decrypt(aes_key, encrypted), aes_key

    def encrypt_answer(self, answer: bytes, aes_key: bytes):
        return aes_encrypt(aes_key, answer)

    def decrypt_answer(self, answer: bytes, aes_key: bytes):
        return aes_decrypt(aes_key, answer)
