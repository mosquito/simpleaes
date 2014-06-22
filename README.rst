Simple AES
==========

Very simple encryption helper for pycripto

Installation
++++++++++++

        pip install SimpleAES

Using
+++++

    >>> from simple_aes import SimpleAES
    >>> enc = SimpleAES('test', use_salt=True)
    >>> encrypted = enc.encrypt('test')
    >>> enc.decrypt(encrypted)
    'test'

Parameter "use_salt" use salted alhotithm. You get different encrypted values each times.
But you must be carefull. This makes encryption of weaker.

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

This write data to file with encrypting and LZMA compression.