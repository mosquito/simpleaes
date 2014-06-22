Simple AES
==========

Very simple encryption helper for pycripto

Installation
++++++++++++

        pip install simple-aes

Using
+++++

    >>> from simple_aes import SimpleAES
    >>> enc = SimpleAES('test', use_salt=True)
    >>> encrypted = enc.encrypt('test')
    >>> enc.decrypt(encrypted)
    'test'

Parameter "use salt" use salted algorithm. You get different encrypted values each times.
But you must be careful. Sometimes this may make encryption of weaker. I will try to explain it.
If you try to encrypt identical phrase more times with salt in theory your encryption key may be opened via differential analysis.
But when you sure what you not doing it, it's makes encryption stronger.

Encrypting big files
++++++++++++++++++++

For encrypting big files you may using EncryptIO like this:

    >>> print "Encrypting..."
    >>> f = EncryptIO('secret', open('test', 'wb+'))
    >>> f.write('Hello world 1024 times. ' * 1024)
    >>> f.close()
    >>> d = EncryptIO('secret', open('test', 'rb'))
    >>> print "Decrypting..."
    >>> data = ''
    >>> for i in d.decrypt():
    ...     data += i
    >>> print data

This write data to file with encrypting and ZLIB compression.
You may change compressor via changing class-property COMPRESSOR.
