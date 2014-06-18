# encoding: utf-8
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import base64


class SimpleAES:
    """
        >>> from simple_aes import SimpleAES
        >>> enc = SimpleAES('test')
        >>> encrypted = enc.encrypt('test')
        >>> enc.decrypt(encrypted)
        'test'
    """
    BLOCK_SIZE = AES.block_size
    JUSTER = "\0"

    def __init__( self, key, use_salt=False):
        self.key = hashlib.md5(key).hexdigest()
        self.use_salt = use_salt

    def _get_salt(self):
        return Random.new().read(AES.block_size)

    def _get_cipher(self, iv=None):
        if self.use_salt:
            return AES.new( self.key, AES.MODE_CBC, self._get_salt() if iv is None else iv)
        else:
            return AES.new( self.key, AES.MODE_ECB)

    def _pad(self, s, juster=JUSTER, block=BLOCK_SIZE):
        length = len(s)
        to_fill = length + (block - length % block)
        return s.ljust(to_fill, juster)

    def _unpad(self, s, juster=JUSTER):
        return s.rstrip(juster)

    def encrypt( self, data):
        padded = self._pad(data)
        cipher = self._get_cipher()
        if self.use_salt:
            out = '{0}{1}'.format(cipher.IV, cipher.encrypt(padded))
        else:
            out = cipher.encrypt(padded)

        return base64.urlsafe_b64encode(out).rstrip('=')

    def decrypt( self, enc ):
        enc = base64.urlsafe_b64decode(self._pad(enc, juster='=', block=4))
        if self.use_salt:
            iv, data = enc[:self.BLOCK_SIZE], enc[self.BLOCK_SIZE:]
        else:
            iv = None
            data = enc

        cipher = self._get_cipher(iv=iv)
        return self._unpad(cipher.decrypt(data))