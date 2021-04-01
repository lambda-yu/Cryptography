#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

struct Key {
    /* data */
    char* public_key;
    char* private_key;
};

struct Key Gen_key(int key_lenth);
long  b64_encode(char* msg, long msg_len, char **out_msg);
long  b64_decode(char* msg, long bytes_len, char **out_msg);
int get_memory(char* src, long src_size, char* dest, int start_index, int stop_index);
long public_key_encrypt(char* public_key, char* plainStr, char** out_msg);
long private_key_decrypt(char* private_key, char* b64_cipherStr, long b64_str_len, char** out_msg);


int main() {
    // ------------------gen key test-------------------
//     struct Key key;
//     key = Gen_key(4096);
//     printf("%s", key.private_key);
//     printf("%s", key.public_key);

    // ------------------encode&decode test-------------------
    char *public_key = "-----BEGIN RSA PUBLIC KEY-----\nMIICCgKCAgEAqY/TkB8TJD/b5HlwwJtufJugdBKpnFA9ZvKCDVk/vjrZEP147MCL\nCoptZbZKj/o3QbyP11fEGYouZSK0x0ChkSymDvfGgU6iCv3I+0N2qXTNaEl92XT/\nKSNLirAb0kgAeZ7RZp6J1Lqnk751Kw3YSrP9yYfOeEu1U3e/KzH8co6kyc/JWwdV\n9jFDy0K32vuU/SAorrMmImhNmZedCJhso2GDxKhsG5KTleMz5H67E9To43ggcDjC\nlrRaxdVHQEKXNPfWJqW1+mnmmpQpJxhAi3ezCSgBD2yTf4WGU68VdvR7rbmKp7a5\nu3pvI7QpRCtgapOkjygrKUwiNgbIpYGbr9PubvSJ/JvxSx+bjWcbFSNQGFg/08yE\nH6KuUHwbH0xGPt3+4K/t555yd1RF7Eu5kkn6FPbdGZyOY99W3Xiw5NWOBe+GjSE0\n0CoQfY0Kr/u0Xna9gz7gXnyqufxjhfojXOTcNWzor0rgOImS03p+k8G/H0MY1m2O\nWh6iOMcU9lDfc5qjrGZ7ceGPZXcrMUNLvbr+E7c4CGqwJjchGIZ3ipZCjU2+ypPr\nFkH2VGdgXF54K17EC8nGl48/S/Wig1Ja5Jny1sbVmX+8zLVQxE5aImLWYuaSwxVk\npptcR8UcelYVXLkD2ATtf5zaekL04nc/Z/TyflKHfhZv+q6TVo3SNTcCAwEAAQ==\n-----END RSA PUBLIC KEY-----\n";
    char *private_key = "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n";

    char *msg, *out_msg, *plain_msg;
    long len, len2;
    msg = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    len = public_key_encrypt(public_key, msg, &out_msg);
    printf("%s\n", out_msg);

    len2 = private_key_decrypt(private_key, out_msg, strlen(out_msg), &plain_msg);
    printf("decode_msg:%s\n", plain_msg);
    free(plain_msg);
    free(out_msg);



    // ------------------base64 test-------------------
//    char * data, *out_data;
//    long len, len2;
//    char *msg_test = "12342222222222222222222222222222222222";
//    len = b64_encode(msg_test, (long)strlen(msg_test), &out_data);
//    printf("%s-%ld\n", out_data, len);
//
//    len2 = b64_decode(out_data, strlen(out_data), &data);
//    printf("decode_msg:%s-%ld\n", data, len2);
//
//    free(out_data);
//    free(data);

}

void c_free(void * p){
    free(p);
}

long public_key_encrypt(char* public_key, char* plainStr, char** out_msg) {
    /*
    * 循环加密，每一段100个字符
    */
    BIO* public_key_bio = BIO_new(BIO_s_mem());
    RSA* rsa = NULL;
    int cipher_size;
    char *cipherStr;
    BIO_write(public_key_bio, public_key, strlen(public_key));
    BIO_flush(public_key_bio);
    rsa = PEM_read_bio_RSAPublicKey(public_key_bio, NULL, NULL, NULL);
    cipher_size = RSA_size(rsa);
    int seq = 100;
    int encrypt_count = (int)(strlen(plainStr) / seq + 1);
    cipherStr = (char*)malloc(cipher_size * encrypt_count);

    char* plain_child, *cipher_child;
    plain_child = (char*)calloc(100, sizeof(char));
    cipher_child = (char*)calloc(cipher_size, sizeof(char));
    for (int i = 0; i < encrypt_count; i++){
        get_memory(plainStr, strlen(plainStr), plain_child, i * 100, (i + 1) * 100);
        long bytes_len = RSA_public_encrypt(strlen(plain_child), plain_child, cipher_child, rsa, RSA_PKCS1_PADDING);
        memcpy(cipherStr + i * cipher_size, cipher_child, cipher_size);
    }

    // base64
    long b64_data_len = b64_encode(cipherStr, cipher_size * encrypt_count, out_msg);

    // free
    BIO_free_all(public_key_bio);
    RSA_free(rsa);
    free(plain_child);
    free(cipher_child);
    free(cipherStr);
    return b64_data_len;
}

long private_key_decrypt(char* private_key, char* b64_cipherStr, long b64_str_len, char** out_msg) {
    /*
    * 循环解密,每段
    */
    BIO* private_key_bio = BIO_new(BIO_s_mem());
    RSA* rsa = NULL;
    BIO_write(private_key_bio, private_key, strlen(private_key));
    BIO_flush(private_key_bio);
    rsa = PEM_read_bio_RSAPrivateKey(private_key_bio, NULL, NULL, NULL);
    long flen = RSA_size(rsa);
    char *cipherStr;
    long cipherStr_len = b64_decode(b64_cipherStr, b64_str_len, &cipherStr);
    long cipher_length, encrypt_count;
    // get cipher length
    /* base64 before and after length
    * if (beforeEncode.length()%3) == 0
    *  aftEncode.length = (beforeEncode.length()/3)*4
    * if (beforeEncode.length()%3) != 0
    *  aftEncode.length = (beforeEncode.length()/3+1)*4
    */
    encrypt_count = (int)(((cipherStr_len / 4) * 3) / flen) + 1;
    cipher_length = encrypt_count * flen;

    long plain_count = 0;
    unsigned char* plain_child, *cipher_child;

    *out_msg = (char *)calloc(256*encrypt_count, sizeof(char));
    plain_child = (unsigned char*)malloc(flen*sizeof(char *));
    cipher_child = (unsigned char*)malloc(flen*sizeof(char *));
    for (int i = 0; i < encrypt_count; i++) {
        get_memory(cipherStr, cipher_length, (char *)cipher_child, i * flen, (i + 1) * flen);
        long bytes_len = RSA_private_decrypt(flen, (unsigned char*)cipher_child, plain_child, rsa, RSA_PKCS1_PADDING);
        memcpy((*out_msg) + plain_count, plain_child, bytes_len);
        plain_count += bytes_len;
    }
    (*out_msg)[plain_count] = '\0';
    BIO_free_all(private_key_bio);
    RSA_free(rsa);
    free(cipherStr);
    free(plain_child);
    free(cipher_child);
    return plain_count;
}

struct Key Gen_key(int key_lenth) {
    // general RSA key
    struct Key key;
    if (key_lenth % 1024 != 0){
        key.private_key = NULL;
        key.public_key = NULL;
        return key;
    }

    int ret;
    char* pub_out = NULL;
    char* pri_out = NULL;
    RSA* rsa = NULL;
    BIGNUM* bne = NULL;
    BIO* private_key = BIO_new(BIO_s_mem());
    BIO* public_key = BIO_new(BIO_s_mem());

    //gen key
    bne = BN_new();
    ret = BN_set_word(bne, 65537);
    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, key_lenth, bne, NULL);
    PEM_write_bio_RSAPrivateKey(private_key, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(public_key, rsa);

    // read private key
    pri_out = (char*)OPENSSL_malloc(key_lenth);
    BIO_read(private_key, pri_out, key_lenth);

    // read public key
    pub_out = (char*)OPENSSL_malloc(key_lenth);
    BIO_read(public_key, pub_out, key_lenth);

    key.private_key = pri_out;
    key.public_key = pub_out;
    return key;
}

int get_memory(char* src, long src_size, char* dest, int start_index, int stop_index) {
    int inner_index = 0;
    if ((start_index < stop_index)&(src_size <= 0)&(stop_index > src_size)) {
        return -1;
    }
    for (int i = start_index; i < stop_index; i++) {
        (dest)[inner_index] = src[i];
        inner_index++;
    }
    (dest)[inner_index] = '\0';
    return 1;

}

long b64_encode(char* msg, long msg_len, char **out_msg) {
    BIO* b64, * bio;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, msg, (int)msg_len);
    BIO_flush(b64);
    char *b64_encode_msg;

    long bytes_len = BIO_get_mem_data(b64, &b64_encode_msg);
    *out_msg = (char *)calloc(bytes_len+1, sizeof(char));
    memcpy(*out_msg, b64_encode_msg, bytes_len);
    BIO_free_all(b64);
    return bytes_len;
}

long b64_decode(char* encoded_bytes, long bytes_len, char **out_msg) {
    BIO* bioMem, * b64;
    *out_msg = (char*)calloc(bytes_len, sizeof(char));
    bioMem = BIO_new_mem_buf(encoded_bytes, (int)bytes_len);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bioMem = BIO_push(b64, bioMem);
    BIO_flush(b64);
    BIO_get_mem_data(bioMem, NULL);

    long len = BIO_read(bioMem, *out_msg, (int)bytes_len);
    BIO_free_all(b64);
    return len;
}