# -*- coding: utf-8 -*-
"""
Created on Wed Sep 15 11:57:26 2021

@author: malfr
"""
import hashlib as hash
import base58 as b58
import sys

#Domain maximum of over the Field P (hex)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
#The a and b values for the
#secp256k1 elliptical curve equation (y^2 = x^3 + ax + b)
A = 0
B = 7
#The x and y values of the Generator Point of the secp256k1 (hex) 
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx,Gy)
#The order N of G
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

"""
End of Parameters
"""

"""
Functions required to perform Ellipitical Curve Operations
"""

#Elliptic Curve Point Addition
def PointAdd(a, b):
    Beta = ((b[1]-a[1]) * inverse_of(b[0]-a[0], P)) % P
    x = (Beta*Beta-a[0]-b[0]) % P
    y = (Beta*(a[0]-x)-a[1]) % P
    return(x,y)

#Elliptic Curve Point Doubling
def PointDouble(a):
   
    Beta = ((3*a[0]*a[0]+A) * inverse_of((2*a[1]),P)) % P
    x = (Beta*Beta-2*a[0]) % P
    y = (Beta*(a[0]-x)-a[1]) % P
    return (x,y)

#Elliptic Curve Cryptography Scalar Multiplication using double and add method
def ECMultiply(generatorPt, hexScalar):
    
    if (hexScalar == 0) or (hexScalar >= N):
        raise Exception("Invalid Private Key")
        
    scalarBinary = str(bin(hexScalar))[2:]
    Q = generatorPt
    #uses double and add method to compute xP
    for bit in range(1,len(scalarBinary)):
        Q = PointDouble(Q)
        if(scalarBinary[bit] == '1'):
            Q = PointAdd(generatorPt, Q)
    return (Q)
"""
Helper functions
"""

def extended_euclidean_algorithm(a, b):
    """
    Returns a three-tuple (gcd, x, y) such that
    a * x + b * y == gcd, where gcd is the greatest
    common divisor of a and b.

    This function implements the extended Euclidean
    algorithm and runs in O(log b) in the worst case.
    """
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = b, a

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t

def inverse_of(n, p):
    """
    Returns the multiplicative inverse of
    n modulo p.

    This function returns an integer m such that
    (n * m) % p == 1.
    """
    gcd, x, y = extended_euclidean_algorithm(n, p)
    assert (n * x + p * y) % p == gcd

    if gcd != 1:
        # Either n is 0, or p is not a prime number.
        raise ValueError(
            '{} has no multiplicative inverse '
            'modulo {}'.format(n, p))
    else:
        return x % p
"""
Hash Functions
"""
#converts hexstring into a byte array (returns bytearray)
def byteForm(hexstring):
    return bytearray.fromhex(hexstring)

#simplified call for the sha256 hash (returns hex string)
def sha256(byteArray):
    #encoded=string.encode()
    return hash.sha256(byteArray).hexdigest()

#simplified call for the ripemd160 hash (returns hex string)
def ripemd160(byteArray):
    #encoded=string.encode()
    return hash.new('ripemd160', byteArray).hexdigest()

#creates the checksum value for base58 encoding  scheme (returns bytearray)
def Checksum(byteArray):
    hashstring = sha256(byteForm(sha256(byteArray)))
    return byteForm(hashstring[:8])

#generates the public key that corresponds to given private key (returns 32 byte public key as hex string)
def createPubKey(privateKey):
    Q = ECMultiply(G, privateKey)
    pubkey = hex(Q[0])[2:]
    return pubkey

#creates the o-coin address using a public key
def createAddress(pubKey, networkByte):
    keyByte = byteForm(pubKey)
    hash1 = sha256(keyByte)
    keyByte = byteForm(hash1)
    hash2 = ripemd160(keyByte)
    #partial address created using network byte and result from above hashing
    partialAddress = byteForm(networkByte + hash2)
    #checksum for partial address is created and appended to partial address to create the unencoded address
    checksum = Checksum(partialAddress)
    unencodedAddress = partialAddress + checksum
    #final address encoded to base58 then returned
    address = str(b58.b58encode(unencodedAddress))[2:-1]
    return address
    
def o_coin_address(pubKey):
    return createAddress(pubKey, "72")
############################################################################################################
if(len(sys.argv) > 1):
    for i in range(1,len(sys.argv)):
        print("address for", sys.argv[i], ":", o_coin_address(sys.argv[i]))