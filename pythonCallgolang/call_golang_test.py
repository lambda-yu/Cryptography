import time
from ctypes import *

class GoSlice(Structure):
    _fields_ = [("data", POINTER(c_void_p)),
                ("len", c_longlong),
                ("cap", c_longlong)]


class go_string(Structure):
    _fields_ = [
        ("p", c_char_p),
        ("n", c_longlong)]


class Keys(Structure):
    _fields_ = [
        ("publicKey", c_char_p),
        ("privateKey", c_char_p),
    ]


go_rsa = CDLL("./rsa.so")
go_rsa.generatekey.restype = Keys

# generateKey test
go_rsa.generatekey.argtypes = [c_int]
go_rsa.generatekey.restype = Keys
keys = go_rsa.generatekey(4096)
print(keys.publicKey, keys.privateKey)

# RsaEncrypt
go_rsa.RsaEncrypt.restype = c_char_p
msg = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"

en_str = go_rsa.RsaEncrypt(c_char_p(msg.encode()), c_char_p(keys.publicKey))

print(en_str.decode())
print(time.time())
# RsaDecrypt
go_rsa.RsaDecrypt.restype = c_char_p
de_msg = go_rsa.RsaDecrypt(c_char_p(en_str), c_char_p(keys.privateKey))
print(time.time())
print(de_msg.decode())


