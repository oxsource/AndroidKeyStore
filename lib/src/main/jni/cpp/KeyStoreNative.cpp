//
// Created by peng on 2022/5/15.
//

#include <jni.h>
#include "KeyStore.h"

extern "C"
JNIEXPORT void JNICALL
Java_com_pizzk_keystore_KeyStore_init(JNIEnv *env, jobject thiz, jstring path) {
    // TODO: implement init()
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_salts(JNIEnv *env, jobject thiz) {
    // TODO: implement salts()
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_encryptAES(JNIEnv *env, jobject thiz, jstring key, jstring value,
                                            jstring mode) {
    // TODO: implement encryptAES()
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_decodeAES(JNIEnv *env, jobject thiz, jstring key, jstring value,
                                           jstring mode) {
    // TODO: implement decodeAES()
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_encryptRSA(JNIEnv *env, jobject thiz, jstring value,
                                            jstring delimiter) {
    // TODO: implement encryptRSA()
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_decodeRSA(JNIEnv *env, jobject thiz, jstring value,
                                           jstring delimiter) {
    // TODO: implement decodeRSA()
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_pizzk_keystore_KeyStore_md5(JNIEnv *env, jobject thiz, jstring value) {
    // TODO: implement md5()
}