# odns-local
Local proxy that cyphers requests according to the ODNS system

# How the crypto in the paper works

## The client Encrypts a question for the server
1. Generate a AES symeric key `AES_k`, an a `nonce`
2. Encrypt the payload with AES `payload = AES(question, AES_k, nonce)`
3. Generate an emphemeral `secp256k1` key pair : `pk1/sk1`
4. Get the server key : `pk2`
5. Perform ECDH exchange to get the ECIES key : `ECIES_k = ECDH(pk2, sk1)`
6. Generate a `nonce`
7. Encrypt the `AES_k` with AES `preamble = AES(AES_k, ECIES_key, nonce)`
8. Create the message : `message = pk1 || nonce || preamble || payload`

## The server decrypts the question
1. Parse the message `pk1 || nonce || preamble || payload = message`
2. Perform ECDH exchange : `ECIES_k = ECDH(sk2, pk1)`
3. Decrypt the preamble : `AES_k = AES_Decrypt(preamble, ECIES_k, nonce)`
4. Decrypt the payload : `question = AES_Decrypt(data, AES_k)`

## The server encrypts the answer
1. Encrypt the answer : `message = AES(answer, AES_k)`

## The client decrypts the answer
1. Decrypt the answer : `answer = AES_Decrypt(message, AES_k)`

# How the crypto could work
## The client Encrypts a question for the server
1. Generate an ephemeral `secp256k1` key pair : `pk1/sk1`
2. Get the server key : `pk2`
3. Perform ECDH exchange to get the ECIES key : `ECIES_k = ECDH(pk2, sk1)`
4. Generate a `nonce`
5. Encrypt the payload with AES `payload = AES(question, ECIES_k, nonce)`
6. Create the message : `message = pk1 || nonce || payload`

## The server decrypts the question
1. Parse the message `pk1 || nonce || payload = message`
2. Perform ECDH exchange : `ECIES_k = ECDH(sk2, pk1)`
4. Decrypt the payload : `question = AES_Decrypt(payload, ECIES_k)`

## The server encrypts the answer
1. Encrypt the answer : `message = AES(answer, ECIES_k)`

## The client decrypts the answer
1. Decrypt the answer : `answer = AES_Decrypt(message, ECIES_k)`
