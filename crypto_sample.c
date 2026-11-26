#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/des.h>

// 1. 弱哈希算法测试 (MD5)
void test_weak_hash(const unsigned char *data, size_t len) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(data, len, digest);
}

// 2. 弱对称加密算法测试 (DES)
void test_weak_cipher() {
    DES_cblock key;
    DES_key_schedule schedule;
    DES_random_key(&key);
    DES_set_key_checked(&key, &schedule);
}

// 3. 短密钥非对称加密测试 (RSA-1024，触发 Key Size < 2048 规则)
void test_short_rsa() {
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, bne, NULL);
    RSA_free(rsa);
    BN_free(bne);
}

// 4. 强加密算法测试 (AES-256-GCM)
void test_strong_aes() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32] = {0};
    unsigned char iv[12] = {0};
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_CIPHER_CTX_free(ctx);
}
