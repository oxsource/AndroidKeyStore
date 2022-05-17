package com.pizzk.keystore

object KeyStore {
    external fun init(path: String?, mode: String?, signature: String?): Boolean

    external fun encryptAES(key: String?, value: String?, mode: String?): String

    external fun decodeAES(key: String?, value: String?, mode: String?): String

    external fun encryptRSA(value: String?, delimiter: String?): String

    external fun decodeRSA(value: String?, delimiter: String?): String

    external fun md5(value: String?): String

    external fun release()

    init {
        System.loadLibrary("crypto")
        System.loadLibrary("ssl")
        System.loadLibrary("keystore")
    }
}