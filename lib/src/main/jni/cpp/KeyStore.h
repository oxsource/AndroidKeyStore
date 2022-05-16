#ifndef KEY_STORE
#define KEY_STORE

#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "KeyChain.h"

class KeyStore {
protected:
    //客户端私钥主密钥，用于解密p12文件
    char *secret;
    //初始化向量
    unsigned char *iv;
    //秘钥链
    KeyChain *chains;
    //客户端私钥
    EVP_PKEY *prvKey;
    //服务端公钥
    EVP_PKEY *pubKey;

    /**通过文件路径解析客户端私钥证书*/
    virtual int initPrvKey(const char *path);

    /**通过文件路径解析服务端公钥*/
    virtual int initPubKey(const char *path);

    /**添加秘钥对*/
    virtual void appendChain(const char *name, const char *value);

public:
    KeyStore();

    ~KeyStore();

    /**通过指定配置文件解析秘钥相关配置*/
    virtual int init(const char *path, const char *secret);

    /**通过名称获取秘钥*/
    virtual const char *key(const char *name);

    /**栅栏混合得到最终秘钥*/
    virtual char *fence(const char *name, const char *value);

    /**盐值*/
    virtual const char *salts();

    /**AES加密*/
    virtual unsigned char *encryptAES(const char *key, const unsigned char *in, int len);

    /**AES解密*/
    virtual unsigned char *decodeAES(const char *key, const unsigned char *in, int len);

    /**服务端RSA公钥加密*/
    virtual unsigned char *encryptRSA(const unsigned char *in, int len, int &out, const char *delimiter);

    /**客户端RSA私钥解密*/
    virtual unsigned char *decodeRSA(const unsigned char *in, int len, int &out, const char *delimiter);

    /**base64 编码*/
    virtual char *encodeB64(const unsigned char *in, int len);

    /**base64 解码*/
    virtual unsigned char *decodeB64(const char *in, int &len);

    /**hex 编码*/
    virtual char *encodeHex(const unsigned char *in, int len);

    /**hex 解码*/
    virtual unsigned char *decodeHex(const char *in, int &len);

    /**MD5计算*/
    virtual char *md5(const char *data);
};

#endif