# The Protocol
In this assignment, you will implement a one-sided authenticated key-exchange protocol between Alice and the server. This will be a slightly simplified variant of a hand-shake protocol that occurs in TLSv1.3 which you use all the time when you browse the web.
Client Alice will establish a connection over an insecure communication channel to the server. Then she will run a one-sided authenticated key-exchange protocol in which a shared secret will be created to secure subsequent communication.
Initially, the protocol will only authenticate the server while Alice's identity will remain unconfirmed. To also authenticate Alice, the server will send a password challenge to which Alice will have to correctly respond. When done so, her identity will be confirmed.

## Initial setting
Server is using an RSA public-secret key pair denoted as (pk, sk). Alice is assumed to know the public key pk in advance.
Alice does not have a keypair. Instead, she uses a password pwd. Similarly, this password is also known to the server.
In code, define the keypair and the password globaly in the method main(String[]) so that Alice and Server can both access it. However, don't access the secret key from within the agent Alice: she may only use the public key pk and the password pwd. The server, however, may also use the secret key sk.

## Detailed description
Detailed description
The protocol contains the following steps. At the end, you'll find a diagram that provides an overview.

1. Alice begins by initiating the Diffie-Hellman key exchange protocol. Use the Elliptic Curve variant as we did in the labs; a good starting point for the assignment is the isp-keyagreement project.
Alice creates her secret value a and computes her public value A = g mod p. (While the notation might suggest the DH protocol is using the arithmetic modulo prime numbers, use the Elliptic curve variant.)
She then sends the public value A to the server.

2. Similarly, server picks its own secret value b and computes its public value B = gb mod p. It then receives Alice's public value A, and combines it with its own secret value to obtain the Diffie-Hellman shared secret.
This value is then immediately hashed with SHA-256 and from the result an AES symmetric key is derived: k = H(Ab mod p). Since the hash will have 32-bytes, and the key requires only 16-bytes, take the first 16-bytes as the key.
Next, the server concatenates Alice's public value A and its own public value B and signs the result using RSA signing algorithm using SHA-256 and its secret key sk: o = S(sk, A||B).
While the pair B, o should be sufficient to prove to Alice that the server is genuine, the server cannot be sure whether Alice is really Alice - it might be someone impersonating her.
So the server issues a password-based challenge to Alice: the server will pick a random 256-bit (32-byte) value chall, symmetrically encrypt it with the just derived symmetric key k using AES in GCM mode and send its encrypted value Cchall E(k, chall) to Alice, along with the DH public value B and the signature σ.

3. Alice receives the messages and immediately verifies the signature o. If the signature fails to verify, the protocol is aborted.
If the signature verifies, she computes the secret key k like the server: k = H(Bª mod p). She then uses AES-GCM to decrypt the challenge: chall D(k, Cchall).
Next, she creates the response by appending the challenge chall to the password pwd and hashing the result with SHA-256: resp = H(pwd||chall).
Finally she encrypts the response Cresp E(k, resp) and sends the Cresp to the server. She is now done.

4. Server receives the ciphertext Cresp and decrypts it: respD(k, Cresp).
Finally, the server verifies the response: it hashes the concatenation of Alices password and the challenge value H(pwd||chall) and compares the result with the decrypted response resp: if they match, Alice is authenticated. If not, the protocol is aborted.
If the protocol terminates succesfully, both Alice and the server are authenticated and they have a shared secret key k which can be used to symmetrically encrypt and authenticate data.