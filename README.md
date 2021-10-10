# blockchain
Code that I have developed for use in my blockchain development.
Included files:
- secp256k1.py: An implementation of Elliptic Curve Multiplication using the secp256k1 curve for private key/public key cryptography (Takes n number of private Keys *inputted as HEXADECIMAL in the command line* and returns n compressed (only the x value) public keys that correspond to those private keys)
- address.py: An implementation of the algorithm used to generate the o-coin (potential name of cryptocurrency created by this protocol) address. (similar to bitcoin's adddress   scheme; Takes n public keys *inputted as HEXADECIMAL in the command line* and returns the n o-coin addresses that correspond to those public keys; requires base58 import)
