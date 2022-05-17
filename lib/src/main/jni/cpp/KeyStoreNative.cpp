//
// Created by peng on 2022/5/15.
//

#include <jni.h>
#include "KeyStore.h"

KeyStore *ks = nullptr;

jstring callAES(JNIEnv *env, jstring key, jstring value, jstring mode, bool encrypt) {
    if (ks == nullptr || mode == nullptr) return env->NewStringUTF("");
    if (key == nullptr || value == nullptr) return env->NewStringUTF("");
    const char *keys = env->GetStringUTFChars(key, nullptr);
    const char *modes = env->GetStringUTFChars(mode, nullptr);
    const char *fences = ks->fence(modes, keys);
    env->ReleaseStringUTFChars(key, keys);
    env->ReleaseStringUTFChars(mode, modes);
    if (fences == nullptr) return nullptr;
    const char *values = env->GetStringUTFChars(value, nullptr);
    int out = 0, len = env->GetStringUTFLength(value);
    const unsigned char *in = encrypt ? (unsigned char *) values : ks->decodeB64(values, len);
    unsigned char *aes = encrypt ? ks->encryptAES(fences, in, len) : ks->decodeAES(fences, in, len);
    env->ReleaseStringUTFChars(value, values);
    if (!encrypt && in != nullptr) { free((char *) in); }
    if (aes == nullptr) return env->NewStringUTF("");
    const char *chs = encrypt ? ks->encodeB64(aes, out) : (char *) aes;
    if (encrypt) { free(aes); }
    const char *bytes = chs == nullptr ? "" : chs;
    return env->NewStringUTF(bytes);
}

jstring callRSA(JNIEnv *env, jstring value, jstring delimiter, bool encrypt) {
    if (ks == nullptr || value == nullptr) return env->NewStringUTF("");
    const char *values = env->GetStringUTFChars(value, nullptr);
    const char *dls = delimiter == nullptr ? "" : env->GetStringUTFChars(delimiter, nullptr);
    int out = 0, len = env->GetStringUTFLength(value);
    const unsigned char *in = encrypt ? (unsigned char *) values : ks->decodeB64(values, len);
    unsigned char *rsa = encrypt ? ks->encryptRSA(in, len, out, dls)
                                 : ks->decodeRSA(in, len, out, dls);
    env->ReleaseStringUTFChars(value, values);
    if (!encrypt && in != nullptr) { free((char *) in); }
    if (delimiter != nullptr) { env->ReleaseStringUTFChars(delimiter, dls); }
    if (rsa == nullptr) return env->NewStringUTF("");
    const char *chs = encrypt ? ks->encodeB64(rsa, out) : (char *) rsa;
    if (encrypt) { free(rsa); }
    const char *bytes = chs == nullptr ? "" : chs;
    return env->NewStringUTF(bytes);
}


extern "C"
JNIEXPORT jboolean JNICALL
Java_com_pizzk_keystore_KeyStore_init(JNIEnv *env, jobject thiz,
                                      jstring path, jstring mode, jstring signature) {

    if (path == nullptr || mode == nullptr || signature == nullptr) return false;
    if (ks == nullptr) { ks = new KeyStore(); }
    const char *paths = env->GetStringUTFChars(path, nullptr);
    const char *modes = env->GetStringUTFChars(mode, nullptr);
    const char *secret = strcmp(modes, "release") == 0 ? "devops1" : "devops";
    int result = ks->init(paths, secret);
    env->ReleaseStringUTFChars(path, paths);
    env->ReleaseStringUTFChars(mode, modes);
    if (result < 0) return false;
    const char *sign = ks->key("signature");
    const char *signs = env->GetStringUTFChars(signature, nullptr);
    bool match = strcmp(sign, signs) == 0;
    env->ReleaseStringUTFChars(signature, signs);
    if (match) return true;
    delete ks;
    ks = nullptr;
    return false;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_encryptAES(JNIEnv *env, jobject jbt,
                                            jstring key, jstring value, jstring mode) {
    return callAES(env, key, value, mode, true);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_decodeAES(JNIEnv *env, jobject jbt, jstring key, jstring value,
                                           jstring mode) {
    return callAES(env, key, value, mode, false);
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_encryptRSA(JNIEnv *env, jobject jbt, jstring value,
                                            jstring delimiter) {
    return callRSA(env, value, delimiter, true);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_decodeRSA(JNIEnv *env, jobject jbt, jstring value,
                                           jstring delimiter) {
    return callRSA(env, value, delimiter, false);
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_md5(JNIEnv *env, jobject jbt, jstring value) {
    if (ks == nullptr || value == nullptr) return env->NewStringUTF("");
    const char *values = env->GetStringUTFChars(value, nullptr);
    const char *salt = ks->salts();
    const char *salts = nullptr == salt ? "" : salt;
    size_t size = strlen(values) + strlen(salts);
    auto data = (char *) malloc(size);
    int offset = (int) strlen(values);
    memcpy(data, values, offset + 0);
    memcpy(data + offset, salts, size - offset);
    env->ReleaseStringUTFChars(value, values);
    char *hex = ks->md5(data);
    const char *chs = hex == nullptr ? "" : hex;
    return env->NewStringUTF(chs);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_pizzk_keystore_KeyStore_release(JNIEnv *env, jobject jbt) {
    delete ks;
    ks = nullptr;
}