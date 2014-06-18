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