#include "KeyStore.h"
#include <cstring>
#include <iostream>

static const char *KEY_SALTS = "salts";
static const char *KEY_X509 = "x509";
static const char *KEY_P12 = "p12";

// protected
int KeyStore::initPrvKey(const char *path) {
    if (this->prvKey != nullptr) {
        return 0;
    }
    std::cout << "---openssl read p12 for rsa---" << std::endl;
    const char *pwd = this->secret;
    if (pwd == nullptr || strlen(pwd) <= 0) {
        std::cout << "pwd is null or empty" << std::endl;
        return -1;
    }
    EVP_PKEY *pkey = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *ca = nullptr;
    PKCS12 *p12;
    // read and parse p12 file
    FILE *fp;
    if ((fp = fopen(path, "rb")) == nullptr) {
        std::cout << "Error opening file" << path << std::endl;
        return -2;
    }
    p12 = d2i_PKCS12_fp(fp, nullptr);
    fclose(fp);
    if (p12 == nullptr) {
        std::cout << "d2i_PKCS12_fp return null" << std::endl;
        return -3;
    }
    if (!PKCS12_parse(p12, pwd, &pkey, &cert, &ca)) {
        std::cout << "Error parsing PKCS#12 file" << std::endl;
        return -4;
    }
    PKCS12_free(p12);
    // https//man.openbsd.org/STACK_OF.3
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);
    this->prvKey = pkey;
    return 0;
}

int KeyStore::initPubKey(const char *path) {
    // read and parse x509 file
    if (this->pubKey != nullptr) {
        return 0;
    }
    FILE *fp;
    if ((fp = fopen(path, "rb")) == nullptr) {
        std::cout << "Error opening file" << path << std::endl;
        return -1;
    }
    X509 *cert = nullptr;
    d2i_X509_fp(fp, &cert);
    fclose(fp);
    if (cert == nullptr) {
        std::cout << "read x509 file failed." << std::endl;
        return -2;
    }
    EVP_PKEY *key = X509_get_pubkey(cert);
    if (key == nullptr) {
        std::cout << "X509_get_pubkey failed." << std::endl;
        return -3;
    }
    this->pubKey = key;
    return 0;
}

void KeyStore::appendChain(const char *name, const char *value) {
    auto *e = new KeyChain();
    e->assign(name, value);
    KeyChain *node = this->chains;
    if (node == nullptr) {
        this->chains = e;
        return;
    }
    while (node != nullptr) {
        if (node->next == nullptr) break;
        node = node->next;
    }
    node->next = e;
}

// public
KeyStore::KeyStore() {
    this->secret = nullptr;
    const char ivs[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7};
    size_t ivs_len = sizeof(ivs);
    this->iv = (unsigned char *) malloc(ivs_len);
    memcpy(this->iv, ivs, ivs_len);
    this->chains = nullptr;
    this->prvKey = nullptr;
    this->pubKey = nullptr;
}

KeyStore::~KeyStore() {
    if (this->secret != nullptr) {
        free(this->secret);
        this->secret = nullptr;
    }
    if (this->iv != nullptr) {
        free(this->iv);
        this->iv = nullptr;
    }
    if (this->chains != nullptr) {
        delete this->chains;
        this->chains = nullptr;
    }
    if (this->prvKey != nullptr) {
        EVP_PKEY_free(this->prvKey);
        this->prvKey = nullptr;
    }
    if (this->pubKey != nullptr) {
        EVP_PKEY_free(this->pubKey);
        this->pubKey = nullptr;
    }
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

int KeyStore::init(const char *path, const char *secrets) {
    size_t secret_len = strlen(secrets);
    this->secret = (char *) malloc(secret_len);
    memcpy(this->secret, secrets, secret_len);
    FILE *fp;
    if ((fp = fopen(path, "rb")) == nullptr) {
        std::cout << "Error opening config file" << path << std::endl;
        return -1;
    }
    char *chs = nullptr;
    size_t len = 0;
    const char *delimiters = "::";
    while ((getline(&chs, &len, fp)) != -1) {
        char *key = strtok(chs, delimiters);
        char *value = key == nullptr ? nullptr : strtok(nullptr, delimiters);
        if (key == nullptr || value == nullptr) {
            continue;
        }
        value = strtok(value, "\n");
        if (strcmp(key, KEY_X509) == 0) {
            this->initPubKey(value);
        } else if (strcmp(key, KEY_P12) == 0) {
            this->initPrvKey(value);
        } else {
            this->appendChain(key, value);
        }
    }
    fclose(fp);
    if (this->prvKey == nullptr) {
        std::cout << "init prvKey config failed." << std::endl;
        return -2;
    }
    // keychain decode by private key
    KeyChain *chain = this->chains;
    int b64_len = 0, rsa_len = 0;
    while (chain != nullptr) {
        char *value = chain->value;
        unsigned char *b64 = this->decodeB64(value, b64_len);
        chain->value = (char *) this->decodeRSA(b64, b64_len, rsa_len, nullptr);
        chain = chain->next;
        if (value != nullptr) { free(value); }
        if (b64 != nullptr) { free(b64); }
    }
    if (this->pubKey == nullptr || this->chains == nullptr) {
        std::cout << "init KeyStore config failed." << std::endl;
        return -3;
    }
    return 0;
}

const char *KeyStore::key(const char *name) {
    KeyChain *e = this->chains;
    while (nullptr != e) {
        if (strcmp(name, e->name) == 0) { break; }
        e = e->next;
    }
    return e != nullptr ? e->value : nullptr;
}

//栅栏数为2(12345678 -> 13572468)
char *KeyStore::fence(const char *name, const char *value) {
    const char *ins = this->key(name);
    if (ins == nullptr || value == nullptr) { return nullptr; }
    size_t ins_len = strlen(ins);
    size_t val_len = strlen(value);
    size_t len = ins_len + val_len;
    char *keys = (char *) malloc(len + 1);
    memset(keys, 0, len + 1);
    if (ins_len != val_len) {
        memcpy(keys, value, val_len);
        return keys;
    }
    for (int i = 0; i < len; ++i) {
        int x = i % 2, y = i / 2;
        const char *source = x == 0 ? ins : value;
        *(keys + i) = *(source + y);
    }
    return keys;
}

const char *KeyStore::salts() {
    return this->key(KEY_SALTS);
}

unsigned char *KeyStore::encryptAES(const char *key, const unsigned char *in, int len) {
    // https://www.openssl.org/docs/man3.0/man3/EVP_EncryptInit.html
    if (key == nullptr || in == nullptr || len <= 0) return nullptr;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, (const unsigned char *) key, this->iv)) {
        EVP_CIPHER_CTX_free(ctx);
        std::cout << "AES EVP_EncryptInit_ex failed." << std::endl;
        return nullptr;
    }
    int updates = 0, finals = 0, size = (len / 16 + 1) * 16;
    auto *values = (unsigned char *) malloc(++size);
    memset(values, 0, size);
    if (!EVP_EncryptUpdate(ctx, values, &updates, in, len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(values);
        std::cout << "AES EVP_EncryptUpdate failed." << std::endl;
        return nullptr;
    }
    if (!EVP_EncryptFinal_ex(ctx, values + updates, &finals)) {
        EVP_CIPHER_CTX_free(ctx);
        free(values);
        std::cout << "AES EVP_EncryptFinal_ex failed." << std::endl;
        return nullptr;
    }
    EVP_CIPHER_CTX_free(ctx);
    int totals = updates + finals;
    values = (unsigned char *) realloc(values, totals + 1);
    values[totals] = '\0';
    return values;
}

unsigned char *KeyStore::decodeAES(const char *key, const unsigned char *in, int len) {
    if (key == nullptr || in == nullptr || len <= 0) return nullptr;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, (const unsigned char *) key, this->iv)) {
        EVP_CIPHER_CTX_free(ctx);
        std::cout << "AES EVP_DecryptInit_ex failed." << std::endl;
        return nullptr;
    }
    int updates = 0, finals = 0;
    auto *values = (unsigned char *) malloc(len);
    memset(values, 0, len);
    if (!EVP_DecryptUpdate(ctx, values, &updates, in, len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(values);
        std::cout << "AES EVP_DecryptUpdate failed." << std::endl;
        return nullptr;
    }
    if (!EVP_DecryptFinal_ex(ctx, values + updates, &finals)) {
        EVP_CIPHER_CTX_free(ctx);
        free(values);
        std::cout << "AES EVP_DecryptFinal_ex failed." << std::endl;
        return nullptr;
    }
    EVP_CIPHER_CTX_free(ctx);
    int totals = updates + finals;
    values = (unsigned char *) realloc(values, totals + 1);
    values[totals] = '\0';
    return values;
}

unsigned char *KeyStore::encryptRSA(const unsigned char *in, int len, int &out, const char *delimiter) {
    // https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_encrypt_init_ex.html
    // https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_new.html
    EVP_PKEY *key = this->pubKey;
    if (in == nullptr || key == nullptr || len <= 0) return nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cout << "RSA EVP_PKEY_encrypt_init failed." << std::endl;
        return nullptr;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cout << "RSA EVP_PKEY_CTX_set_rsa_padding failed." << std::endl;
        return nullptr;
    }
    // RSA_size(rsa) - 11 for the PKCS #1
    int block_size = (int) EVP_PKEY_size(key), rsa_size = block_size - RSA_PKCS1_PADDING_SIZE;
    auto *buffer = (unsigned char *) OPENSSL_malloc(block_size);
    if (buffer == nullptr) {
        EVP_PKEY_CTX_free(ctx);
        std::cout << "RSA EVP_PKEY_encrypt malloc buffer failed." << std::endl;
        return nullptr;
    }
    int offset = 0, reads, seeking = 0, splits;
    int boundary = delimiter == nullptr ? 0 : strlen(delimiter);
    unsigned char *values = (unsigned char *) OPENSSL_malloc(block_size);
    memset(values, 0, block_size);
    size_t sizing;
    while (offset < len) {
        reads = (reads = len - offset) > rsa_size ? rsa_size : reads;
        memset(buffer, 0, (sizing = block_size));
        if (!EVP_PKEY_encrypt(ctx, buffer, &sizing, in + offset, reads)) break;
        int new_size = seeking > 0 ? seeking + sizing + boundary : 0;
        values = new_size > 0 ? (unsigned char *) OPENSSL_realloc(values, new_size) : values;
        //append delimiter
        splits = seeking > 0 && boundary > 0 ? boundary : 0;
        if (splits > 0) { memcpy(values + seeking, delimiter, boundary); }
        seeking += splits;
        //append buffer
        memcpy(values + seeking, buffer, sizing);
        offset += reads, seeking += (int) sizing;
    }
    out = seeking;
    free(buffer);
    EVP_PKEY_CTX_free(ctx);
    return values;
}

unsigned char *KeyStore::decodeRSA(const unsigned char *in, int len, int &out, const char *delimiter) {
    // https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_decrypt_init.html
    EVP_PKEY *key = this->prvKey;
    if (in == nullptr || key == nullptr || len <= 0) return nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, nullptr);
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cout << "RSA EVP_PKEY_decrypt_init failed." << std::endl;
        return nullptr;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cout << "RSA EVP_PKEY_CTX_set_rsa_padding failed." << std::endl;
        return nullptr;
    }
    int block_size = EVP_PKEY_size(key);
    auto *buffer = (unsigned char *) OPENSSL_malloc(block_size);
    if (buffer == nullptr) {
        EVP_PKEY_CTX_free(ctx);
        std::cout << "RSA EVP_PKEY_decrypt malloc buffer failed." << std::endl;
        return nullptr;
    }
    unsigned char *values = nullptr;
    int boundary = delimiter == nullptr ? 0 : strlen(delimiter), seeking = 0;
    size_t sizing;
    for (int i = 0, basis = 0, offset = 0, reads = 0, skips = 0; i < len; i++, offset++) {
        if (boundary > 0 && strncmp((char *) in + i, delimiter, boundary) == 0) {
            //priority 1: block reads by check delimiter limit(block size less than EVP_PKEY_size)
            reads = i - basis, offset = basis, basis = i + boundary;
            i += boundary - 1, skips += boundary;//skip boundary
            //std::cout << "RSA EVP_PKEY_decrypt when delimiter block: " << reads << std::endl;
        } else if (i != basis && (i - basis) % block_size == 0) {
            //priority 2: block reads by block size(EVP_PKEY_size)
            reads = block_size, offset = basis, basis = i;
            //std::cout << "RSA EVP_PKEY_decrypt when EVP_PKEY_size block: " << reads << std::endl;
        } else if (len - basis <= block_size) {
            //priority 3: block reads by check is the last block
            reads = len - skips - basis, offset = basis, basis = len;
            i = len; //stop next loop
            //std::cout << "RSA EVP_PKEY_decrypt when last block: " << reads << std::endl;
        }
        if (reads <= 0) continue;
        memset(buffer, 0, (sizing = block_size));
        if (!EVP_PKEY_decrypt(ctx, buffer, &sizing, in + offset, reads)) break;
        int bsize = seeking + sizing;
        values = (unsigned char *) (values == nullptr ? OPENSSL_malloc(bsize) : OPENSSL_realloc(values, bsize));
        memcpy(values + seeking, buffer, sizing);
        seeking += (int) sizing, reads = 0, offset = 0;
    }
    out = seeking;
    free(buffer);
    EVP_PKEY_CTX_free(ctx);
    return values;
}

char *KeyStore::encodeB64(const unsigned char *in, int len) {
    // https://www.openssl.org/docs/man1.0.2/man3/EVP_EncodeBlock.html
    if (in == nullptr || len <= 0) return nullptr;
    int sizing = (len + 2) / 3 * 4 + 1;
    auto *outs = (unsigned char *) malloc(sizing);
    memset(outs, 0, sizing);
    if (EVP_EncodeBlock(outs, in, len) <= 0) {
        std::cout << "B64 EVP_EncodeBlock failed." << std::endl;
    }
    return (char *) outs;
}

unsigned char *KeyStore::decodeB64(const char *in, int &len) {
    // https://www.openssl.org/docs/man1.0.2/man3/EVP_DecodeBlock.html
    if (in == nullptr) return nullptr;
    int sizing, length = (int) strlen((char *) in);
    len = length * 3 / 4, sizing = len + 1;
    auto *outs = (unsigned char *) malloc(sizing);
    memset(outs, 0, sizing);
    if (EVP_DecodeBlock(outs, (unsigned char *) in, length) <= 0) {
        len = 0;
        std::cout << "B64 EVP_DecodeBlock failed." << std::endl;
    }
    return outs;
}

char *KeyStore::encodeHex(const unsigned char *in, int len) {
    if (in == nullptr || len <= 0) return nullptr;
    int sizing = len * 2 + 1;
    auto *out = (char *) malloc(sizing);
    memset(out, 0, sizing);
    for (int i = 0; i < len; i++) {
        sprintf(&out[i * 2], "%02x", (unsigned int) in[i]);
    }
    return out;
}

unsigned char *KeyStore::decodeHex(const char *in, int &len) {
    int sizing, length = in == nullptr ? 0 : (int) strlen(in);
    if (length <= 0) return nullptr;
    sizing = (length + 1) / 2, len = sizing;
    auto *values = (unsigned char *) malloc(++sizing);
    memset(values, 0, sizing);
    unsigned int value = 0;
    for (int i = 0, offset = 0; i < length; i += 2, offset++) {
        sscanf(in + i, "%02x", &value);
        *(values + offset) = value;
    }
    return values;
}

char *KeyStore::md5(const char *data, bool salts) {
    if (data == nullptr) return nullptr;
    const char *salt = this->salts();
    size_t sizing = strlen(data) + strlen(salt);
    auto *plain = (unsigned char *) malloc(sizing);
    int len = MD5_DIGEST_LENGTH;
    unsigned char digest[len];
    MD5(plain, sizing, (unsigned char *) &digest);
    free(plain);
    return encodeHex((unsigned char *) digest, len);
}