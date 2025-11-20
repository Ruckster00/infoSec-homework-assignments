
# Secrecy
Confidentiality ensures only intended recipients can read messages. Implemented using symmetric or asymmetric encryption.

**Secure Cipher** Cipher text should reveal no information about the plain text.

## Perfect Secrecy
Given cipher text c, one cannot tell whether c is a cryptogram of m_0 or m_1 where k is randomly chosen. So following probibilty equation must hold: P[E(k,m_0)=c] = P[E(k,m_1)=c]

## One Time Pad
**Vernam** 
M=C=K={0,1}^n; E(k,m) = k xor m; D(k,c) = k xor c
- given a truly random key, OTP ha perfect secrecy
- key has to be random and it must be used only once
- BUT: perfect secrecy requires key to be at least as long as the plain text

## Pseudo Random Generator (PRG)
Idea: replace and random with a pseudorandom key
PRG is a deterministic function G that maps seed space to random looking key space: {0,1}^s -> {0,1}^n where n>>s

Stream ciphers
- E(k,m) := m xor G(k)
- D(k,c) := c xor G(k)
- stream ciphers cannot have perfect secrecy because keys (seeds) are shorter than messages

**Def. Secure PRG** For all efficient statistical tests A: Adv_PRG[A,G] is negligible (<2^-80).

**Def. Unpredictable PRG** Given an initial sequence of bits (a prefix), one cannot efficiently predict the next bit (p > 0,5 + number).

**Thm. Secure PRG** A PRG is secure iff. it is unpredictable.

## Threat model
Idea: Basis for reasoning about security
- **Adversary's power** what can she do?
- **Adversary's goal** what is she trying to achieve?
### Def. Semantic Security
**One-Time Semantic Security**

- AP: observer one ciphertext
  - every message is encrypted with its own key; a particular key is used only once
- AG: learn about the plaintext

**Many-Time Semantic Security (CPA-Security)**

- AP: chosen-PT attack
  - can obtain the encryption of any message of her choice
- AG: break semantic security
  - learn about the PT from the CT
  
A cipher has semantic security if given only cipher text, an attacker cannot practically derive any information about the plain text

**Thm.** Given a secure PRG, derived stream cipher is semantically secure.

## Attacks
- **Two-time pad attack** Never use stream-cipher key to encrypt more than one message
  **Look at code example!!!**

- **Malleability attack** Modifications to CT are not detected and have predicatble impact on the plain text

## Block Ciphers
- work on data blocks of fixed sizes (length n) with key of fixed size k produce a ciphertext of n length
- built by iteration
- behave like PRps (pseudorandom permutations F: K x X -> X)
- PRPs are a subset of PRFs (pseudorandom function E: K x X -> Y)
  - E(k,-) has an inverse
  - we have an efficient inversion algorithm D(k,x)
  
**Secure PRF** random function in Funs[X,Y] is indistinguishable from a random function in S_F which is a subset of all functions from X to Y
- definitions of secure PRFs and PRPs

### Modes of Operation
**Electronic Code Book (ECB)**

- split data into blocks and if needed extend the last block with padding bits
- independently encrypt each block 
- PROBLEM: If two plaintext blocks are the same, so are the corresponding ciphertexts blocks
- not semantically secure!! When sending two messages to the challenger you can find out which of the two messages was encryted by choosing m_1 and m_0 correctly

**Deterministic Counter Mode (CTR)**

- creates a stream cipher from a PRF
- secure (but only for encrypting a single message)
- requires unique (key,nonce) pair
- nonce is a counter

**Cipher Block Chaining (CBC)**

- randomize encryption with an initialization vector (IV)
  - sent unencrypted
  - requires new unpredictable IV per message
- forces encryption to be sequential
- secure under CPA

# Integrity
Integrity ensures data has not been altered. Detection is usually sufficient achieved through Message Authentication Codes (MACs).

## Message Authentication Code
Pair (S,V) of signing and verification algorithm:
- S: K x M -> T
- V: K x M x T -> {0,1}
- consistency requirement: V(k,m,S(k,m)) = 1
  
## Secure MAC

- AP: Chosen message attack
  - for any message the attacker is given a corresponding valid tag
- AG: Existential forgery
  - produce a new valid (m,t) pair
- Turn secure PRF F:K x X -> Y into **secure MAC** I_F = (S,V):
  - S(k,m) := F(k,m)
  - V(k,m,t) := if t = F(k,m) ? 1 : 0 
  - if F is a a secure PRF and |Y| is sufficiently large, then I_F is a secure MAC

## MACs for Long Messages
**CBC-/ECBC-MAC**

- uses block cipher PRP repeatedly
- msut use fixed-length messages or fix construction (ECBC)

**Hash-based MACs**

- must be collision resistant (advantage is negligible)
- Merkle-Damgard constructions: given a CR function for short messages (compression fucntion), construct CR function for long messages

**MAC from CR**
If I is a secure MAC and H is collision resistant, then I^BIG is a secure MAC





