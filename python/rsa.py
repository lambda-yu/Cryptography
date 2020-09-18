import base64
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


def gen_key(key_bits:int):
    """生成RSA密钥对"""
    assert key_bits >= 1024, "key_bits must be >= 1024"
    random_gen = Random.new().read
    rsa = RSA.generate(key_bits, random_gen)
    private_key = rsa.exportKey()
    public_key = rsa.publickey().exportKey()
    return public_key.decode(), private_key.decode()


def rsa_encrypt(data, public_key: str, seg_count=None) -> str:
    """
    RSA加密函数，公钥加密
    :param data: 需要被加密的数据
    :param public_key: 公钥字符串 or 公钥路径
    :param seg_count:  分段长度
    :return:
    """
    if len(public_key) <= 150:
        public_key = open(public_key).read()
    public_key = RSA.import_key(public_key)
    pk = PKCS1_v1_5.new(public_key)
    encrypt_text = []
    if seg_count is not None:
        for offset in range(0, len(data), seg_count):
            encrypt_text.append(base64.b64encode(pk.encrypt(data[offset:offset+seg_count].encode())).decode())
    else:
        encrypt_text.append(base64.b64encode(pk.encrypt(data.encode())).decode())
    return "".join(encrypt_text)
    
    
def rsa_decrypt(data, private_key:str) -> str:
    """
    RSA解密函数, 私钥解密
    :param data: 需要被加密的数据
    :param private_key: 公钥字符串 or 公钥路径
    :param seg_count: 分段长度
    :return:
    """
    if len(private_key) <= 150:
        private_key = open(private_key).read()
    random_generator = Random.new().read
    private_key = RSA.import_key(private_key)
    
    pk = PKCS1_v1_5.new(private_key)
    encrypt_text = []
    if private_key.size_in_bits() > 2048:
        seg_count = 171 * int((private_key.size_in_bits() / 1024))
    else:
        seg_count = 172 * int((private_key.size_in_bits() / 1024))
    for offset in range(0, len(data), seg_count):
        encrypt_text.append(pk.decrypt(base64.b64decode(data[offset: offset+seg_count]), random_generator).decode())
    return "".join(encrypt_text)



if __name__ == '__main__':
    pass