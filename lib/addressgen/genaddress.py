#!/usr/bin/env python3
import argparse
import ctypes
import hashlib
import hmac
import sys

from lib.addressgen import base58

################################################################################
################################################################################
DEBUG = False

COINS = {
    'BTC' : {
        'main': {
            'prefix'        : 0,
            'private_prefix': 0x80,
            'bip32_public'  : bytes([0x04, 0x88, 0xb2, 0x1e]),
            'bip32_private' : bytes([0x04, 0x88, 0xad, 0xe4]),
        },
        'test': {
            'prefix'        : 0x6f,
            'private_prefix': 0x6f+0x80,
            'bip32_public'  : bytes([0x04, 0x35, 0x87, 0xcf]),
            'bip32_private' : bytes([0x04, 0x35, 0x83, 0x94]),
        }
    },
    'DOGE' : {
        'main': {
            'prefix'        : 0x1e,
            'private_prefix': 0x1e+0x80,
            'bip32_public'  : bytes([0x02, 0xfa, 0xca, 0xfd]),
            'bip32_private' : bytes([0x02, 0xfa, 0xc3, 0x98]),
        },
        'test': {
            'prefix'        : 0x71,
            'private_prefix': 0x71+0x80,
            'bip32_public'  : bytes([0x04, 0x32, 0xa9, 0xa8]),
            'bip32_private' : bytes([0x04, 0x32, 0xa2, 0x43]),
        }
    },
    'LTC' : {
        'main': {
            'prefix'        : 0x30,
            'private_prefix': 0x30+0x80,
            'bip32_public'  : bytes([0x01, 0x9d, 0xa4, 0x62]),
            'bip32_private' : bytes([0x01, 0x9d, 0x9c, 0xfe]),
        },
        'test': {
            'prefix'        : 0x6f,
            'private_prefix': 0x6f+0x80,
            'bip32_public'  : bytes([0x04, 0x36, 0xf6, 0xe1]),
            'bip32_private' : bytes([0x04, 0x36, 0xef, 0x7d]),
        }
    },
    'PPC' : {
        'main': {
            'prefix'        : 0x37,
            'private_prefix': 0x38+0x80,
        },
        'test': {
            'prefix'        : 0x6f,
            'private_prefix': 0x6f+0x80,
        }
    },
    "GRLC" :{
        'main': {
            'prefix'        : 0x26, #this i correct
            'private_prefix': 0xb0, #this is correct
            'bip32_public'  : bytes([0x01, 0x9d, 0xa4, 0x62]),
            'bip32_private' : bytes([0x01, 0x9d, 0x9c, 0xfe]),
        },
        'test': {
            'prefix'        : 0x6f,
            'private_prefix': 0x6f+0x80,
            'bip32_public'  : bytes([0x04, 0x36, 0xf6, 0xe1]),
            'bip32_private' : bytes([0x04, 0x36, 0xef, 0x7d]),
        }
    }
}

################################################################################
################################################################################
try:
    ssl_library = ctypes.cdll.LoadLibrary('libeay32.dll')
except:
    ssl_library = ctypes.cdll.LoadLibrary('libssl.so')

if DEBUG:
    print("ssl_library is {}".format(ssl_library))

def bytes2hex(data):
    return ''.join([ '{:02x}'.format(v) for v in data ])

def hex2bytes(data):
    return bytes([ int(data[i:i+2], 16) for i in range(0, len(data), 2) ])

NID_secp160k1 = 708
NID_secp256k1 = 714

BIP32_PRIVATE_KEY_BYTES = set([COINS[coin_name][network]['bip32_private'] for coin_name in COINS.keys() for network in ('main', 'test') if 'bip32_private' in COINS[coin_name][network]])
BIP32_PUBLIC_KEY_BYTES = set([COINS[coin_name][network]['bip32_public'] for coin_name in COINS.keys() for network in ('main', 'test') if 'bip32_public' in COINS[coin_name][network]])

def gen_key_pair(curve_name=NID_secp256k1):
    k = ssl_library.EC_KEY_new_by_curve_name(curve_name)

    if ssl_library.EC_KEY_generate_key(k) != 1:
        raise Exception("internal error")

    bignum_private_key = ssl_library.EC_KEY_get0_private_key(k)
    size = (ssl_library.BN_num_bits(bignum_private_key)+7)//8

    if DEBUG:
        print("Private key size is {} bytes".format(size))

    storage = ctypes.create_string_buffer(size)
    ssl_library.BN_bn2bin(bignum_private_key, storage)
    private_key = storage.raw

    if (len(private_key) == size) and size < 32:
        private_key = bytes([0] * (32 - size)) + private_key

    size = ssl_library.i2o_ECPublicKey(k, 0)

    if DEBUG:
        print("Public key size is {} bytes".format(size))

    storage = ctypes.create_string_buffer(size)
    ssl_library.i2o_ECPublicKey(k, ctypes.byref(ctypes.pointer(storage)))
    public_key = storage.raw

    ssl_library.EC_KEY_free(k)
    return public_key, private_key

def get_public_key(private_key, curve_name=NID_secp256k1):
    k = ssl_library.EC_KEY_new_by_curve_name(curve_name)

    storage = ctypes.create_string_buffer(private_key)
    bignum_private_key = ssl_library.BN_new()
    ssl_library.BN_bin2bn(storage, 32, bignum_private_key)

    group = ssl_library.EC_KEY_get0_group(k)
    point = ssl_library.EC_POINT_new(group)

    ssl_library.EC_POINT_mul(group, point, bignum_private_key, None, None, None)
    ssl_library.EC_KEY_set_private_key(k, bignum_private_key)
    ssl_library.EC_KEY_set_public_key(k, point)

    size = ssl_library.i2o_ECPublicKey(k, 0)
    storage = ctypes.create_string_buffer(size)
    pstorage = ctypes.pointer(storage)
    ssl_library.i2o_ECPublicKey(k, ctypes.byref(pstorage))
    public_key = storage.raw

    ssl_library.EC_POINT_free(point)
    ssl_library.BN_free(bignum_private_key)
    ssl_library.EC_KEY_free(k)
    return public_key

def compress(public_key):
    x_coord = public_key[1:33]
    if public_key[64] & 0x01:
        c = bytes([0x03]) + x_coord
    else:
        c = bytes([0x02]) + x_coord
    return c

def decompress(public_key):
    raise Exception("TODO")

def singlehash256(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()

def hash256(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    r = hasher.digest()

    hasher2 = hashlib.sha256()
    hasher2.update(r)
    return hasher2.digest()

def hash160(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    r = hasher.digest()

    hasher2 = hashlib.new('ripemd160')
    hasher2.update(r)
    return hasher2.digest()

def is_public_key(public_key):
    return len(public_key) > 0 and \
           ((public_key[0] == 0x04 and len(public_key) == 65) or \
            (public_key[0] in (0x02, 0x03) and len(public_key) == 3))

def address_from_data(data, version_bytes=0):
    assert isinstance(data, bytes)
    return base58_check(hash160(data), version_bytes=version_bytes)

def base58_check(src, version_bytes=0):
    if isinstance(version_bytes, int):
        version_bytes = bytes([version_bytes])

    src = version_bytes + src

    r = hash256(src)

    if DEBUG:
        print('SHA256(SHA256(0x{} + src)):'.format(bytes2hex(version_bytes)), bytes2hex(r))

    checksum = r[:4]
    s = src + checksum

    if DEBUG:
        print('src + checksum:', bytes2hex(s))

    e = base58.encode(int.from_bytes(s, 'big'))
    if version_bytes == bytes([0]):
        lz = 0
        while lz < len(src) and src[lz] == 0:
            lz += 1

        return ('1' * lz) + e
    return e

def decode_base58_private_key(src):
    decoded = base58.decode(src)
    try:
        # version + private_key + checksum
        decoded_bytes = decoded.to_bytes(37, 'big')

        version_byte = decoded_bytes[0]
        private_key = decoded_bytes[1:33]
        compressed_byte = 0
        checksum = decoded_bytes[33:]
        src = bytes([version_byte]) + private_key

    except OverflowError:
        # version + private_key + compression + checksum
        decoded_bytes = decoded.to_bytes(38, 'big')

        version_byte = decoded_bytes[0]
        private_key = decoded_bytes[1:33]
        compressed_byte = decoded_bytes[33]
        checksum = decoded_bytes[34:]
        src = bytes([version_byte]) + private_key + bytes([compressed_byte])

    s = hash256(src)
    if s[0:4] != checksum:
        raise Exception("invalid private key")

    return version_byte, compressed_byte == 0x01, private_key

def bip32(private_key, coin):
    m = hmac.new('Bitcoin seed'.encode('ascii'), digestmod=hashlib.sha512)
    m.update(private_key)
    s = m.digest()
    il, ir = s[:32], s[32:]

    # Generate a master private key:
    # depth + parent_fingerprint + child_index + chain_code + 0 + private_key
    r = bytes([0]) + bytes([0, 0, 0, 0]) + bytes([0, 0, 0, 0]) + ir + bytes([0]) + il
    bip32_private_key = base58_check(r, version_bytes=coin['bip32_private'])

    # Generate a master public key:
    # depth + parent_fingerprint + child_index + chain_code + compressed_public_key
    r = bytes([0]) + bytes([0, 0, 0, 0]) + bytes([0, 0, 0, 0]) + ir + compress(get_public_key(il))
    bip32_public_key = base58_check(r, version_bytes=coin['bip32_public'])

    return bip32_public_key, bip32_private_key

def bip32_get_public_key(bip32_private_key):
    decoded = base58.decode(bip32_private_key)

    decoded_bytes = decoded.to_bytes(82, 'big')
    if len(decoded_bytes) != 82:
        raise Exception("invalid bip32 key")

    c = hash256(decoded_bytes[0:78])
    if c[0:4] != decoded_bytes[78:]:
        raise Exception("invalid bip32 key")

    if decoded_bytes[0:4] not in BIP32_PRIVATE_KEY_BYTES:
        raise Exception("invalid bip32 key")

    if decoded_bytes[-4-33] != 0:
        raise Exception("invalid bip32 key")

    private_key = decoded_bytes[-4-32:-4]
    r = decoded_bytes[4:-4-33] + compress(get_public_key(private_key))

    coin = None
    for coin_name in COINS:
        for network in ('main', 'test'):
            if 'bip32_private' in COINS[coin_name][network] and decoded_bytes[0:4] == COINS[coin_name][network]['bip32_private']:
                coin = COINS[coin_name][network]
                break

    if coin is None:
        raise Exception("unknown extended private key")

    return base58_check(r, version_bytes=coin['bip32_public'])

def bip32_extract_private_key(bip32_private_key):
    decoded = base58.decode(bip32_private_key)

    decoded_bytes = decoded.to_bytes(82, 'big')
    if len(decoded_bytes) != 82:
        raise Exception("invalid bip32 key")

    c = hash256(decoded_bytes[0:78])
    if c[0:4] != decoded_bytes[78:]:
        raise Exception("invalid bip32 key")

    if decoded_bytes[0:4] not in BIP32_PRIVATE_KEY_BYTES:
        raise Exception("invalid bip32 key")

    if decoded_bytes[-4-33] != 0:
        raise Exception("invalid bip32 key")

    return decoded_bytes[-4-32:-4]

def bip32_extract_public_key(bip32_public_key):
    decoded = base58.decode(bip32_public_key)

    decoded_bytes = decoded.to_bytes(82, 'big')
    if len(decoded_bytes) != 82:
        raise Exception("invalid bip32 key")

    c = hash256(decoded_bytes[0:78])
    if c[0:4] != decoded_bytes[78:]:
        raise Exception("invalid bip32 key")

    if decoded_bytes[0:4] not in BIP32_PUBLIC_KEY_BYTES:
        raise Exception("invalid bip32 key")

    if decoded_bytes[-4-33] not in (0x02, 0x03):
        raise Exception("invalid bip32 key")

    return decoded_bytes[-4-33:-4]


def main(target_coin=None):
    to_return = {} # return string for the return addresses and private key
    args = {}

    coin = COINS[target_coin]["main"]

    bip32_private_key = None
    bip32_public_key = None
    public_key, private_key = gen_key_pair()

    to_return['private_key'] = str(base58_check(private_key, version_bytes=coin['private_prefix']))

    if 'bip32_private' in coin:
        bip32_public_key, bip32_private_key = bip32(private_key, coin)

    if bip32_private_key is not None:
        print("Bitcoin extended private key (Base58Check)\n    {}".format(bip32_private_key))
        #print("    (embedded private key) -> {}".format(base58_check(bip32_extract_private_key(bip32_private_key) + bytes([0x01]), version_bytes=239 if args.testnet else 128)))



    if public_key is not None:
        assert len(public_key) in (33, 65)

        addr = address_from_data(public_key, version_bytes=coin['prefix'])
        print("Bitcoin Address (uncompressed, length={}):\n    {}".format(len(addr), addr))
        to_return['address'] = str(addr)

    if bip32_public_key is not None:
        print("Bitcoin extended public key\n    {}".format(bip32_public_key))
        print("    (embedded public key) -> {}".format(bytes2hex(bip32_extract_public_key(bip32_public_key))))
        print("    (bitcoin address) -> {}".format(base58_check(hash160(bip32_extract_public_key(bip32_public_key)), version_bytes=coin['prefix'])))
    return to_return

def new_grlc_wallet():
    return main("GRLC")
