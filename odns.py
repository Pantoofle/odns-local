from coincurve import PrivateKey, PublicKey
from ecies.utils import generate_key, hex2pub
from ecies.utils import encapsulate, decapsulate, aes_encrypt, aes_decrypt


class ODNSCypher():
    """
        Holding all cryptography algorithms to encrypt and decrypt queries and
        answers.
    """

    def __init__(self, server_sk=None, server_pk=None):
        if server_sk is not None:
            self.server_sk = PrivateKey.from_pem(server_sk)

        self.server_sk = server_sk
        self.server_pk = None

        if server_pk is not None:
            if isinstance(server_pk, str):
                self.server_pk = hex2pub(server_pk)
            elif isinstance(server_pk, bytes):
                self.server_pk = PublicKey(server_pk)
            else:
                raise TypeError("Invalid public key type")

    def encrypt_query(self, query: bytes):
        """
            Encrypt the query to send to the server

            query     - The query
        """
        # Generate the ephemeral key
        ephemeral_key = generate_key()

        # Generate the symetric key
        print("Ephemeral: ", type(ephemeral_key))
        print("Server PK: ", type(self.server_pk))
        aes_key = encapsulate(ephemeral_key, self.server_pk)
        # Encrypt the query (this adds the nonce)
        cipher_text = aes_encrypt(aes_key, query)
        # Return the message and the symetric key
        return ephemeral_key.public_key.format(False) + cipher_text, aes_key

    def decrypt_query(self, query: bytes):
        """
            Decrypts a query received by the server

            query - The query to decrypt
        """
        # Parse the server key

        # Parsre the msg, extract the pubkey and the {IV || payload} from the query
        pubkey = query[0:65]  # uncompressed pubkey's length is 65 bytes
        encrypted = query[65:]
        ephemeral_public_key = PublicKey(pubkey)

        # Generate the AES key
        aes_key = decapsulate(ephemeral_public_key, self.server_sk)
        return aes_decrypt(aes_key, encrypted), aes_key

    def encrypt_answer(self, answer: bytes, aes_key: bytes):
        return aes_encrypt(aes_key, answer)

    def decrypt_answer(self, answer: bytes, aes_key: bytes):
        return aes_decrypt(aes_key, answer)
