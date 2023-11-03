import gzip

import ctypes
import ctypes.util

__SODIUM = None


class SodiumError(Exception):
    pass


class InvalidPassphrase(SodiumError):
    pass


def get_sodium():
    global __SODIUM
    if __SODIUM is None:
        lib = ctypes.util.find_library('sodium') or ctypes.util.find_library('libsodium')
        __SODIUM = ctypes.cdll.LoadLibrary(lib)

        if __SODIUM._name is None:
            raise SodiumError('Could not find libsodium library')

        if __SODIUM.sodium_init() < 0:
            raise SodiumError('Could not initialize libsodium')

        __SODIUM.sodium_version_string.restype = ctypes.c_char_p
        version = __SODIUM.sodium_version_string().decode('utf8')
        if version < '1.0.12':
            raise SodiumError(f'libsodium >= 1.0.12 expected; found {version}')

    return __SODIUM


def decrypt_peek(peek, passphrase) -> bytes:
    meta = peek['meta']
    na = get_sodium()

    out_len = meta['out-len']
    out = ctypes.create_string_buffer(out_len)
    rc = na.crypto_pwhash(
        ctypes.byref(out),
        ctypes.c_ulonglong(out_len),
        passphrase,
        ctypes.c_ulonglong(len(passphrase)),
        meta['salt'],
        ctypes.c_ulonglong(meta['ops-limit']),
        ctypes.c_size_t(meta['mem-limit']),
        ctypes.c_int(na.crypto_pwhash_alg_argon2id13()))

    if rc != 0:
        raise SodiumError('Invalid peek')

    master_key = out.raw

    subkey_len = meta['subkey-len']
    subkey = ctypes.create_string_buffer(subkey_len)

    na.crypto_kdf_derive_from_key(
        subkey,
        subkey_len,
        ctypes.c_ulonglong(meta['subkey-id']),
        meta['subkey-context'],
        master_key)

    return subkey.raw


def decrypt(key, nonced_cipher_text) -> bytes:
    na = get_sodium()
    nonce_size = na.crypto_aead_xchacha20poly1305_ietf_npubbytes()
    nonce = nonced_cipher_text[:nonce_size]
    cipher_text = nonced_cipher_text[nonce_size:]

    out = ctypes.create_string_buffer(
        len(cipher_text) - na.crypto_aead_xchacha20poly1305_ietf_abytes())

    rc = na.crypto_aead_xchacha20poly1305_ietf_decrypt(
        out,
        ctypes.byref(ctypes.c_ulonglong(0)),
        None,
        cipher_text,
        ctypes.c_ulonglong(len(cipher_text)),
        None,
        ctypes.c_ulonglong(0),
        nonce,
        key)

    if rc != 0:
        raise SodiumError('Could not decrypt; invalid key or message')

    if is_gzipped(out.raw):
        return gzip.decompress(out.raw)

    return out.raw


def get_ekey(peek, passphrase) -> bytes:
    pdek = decrypt_peek(peek, passphrase)

    try:
        return decrypt(pdek, peek['value'])
    except SodiumError:
        raise InvalidPassphrase('Invalid passphrase')


def is_gzipped(value) -> bool:
    return len(value) >= 2 and value[:2] == b'\x1f\x8b'
