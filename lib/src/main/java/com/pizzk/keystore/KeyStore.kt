package com.pizzk.keystore

object KeyStore {
    external fun init(path: String)

    external fun salts(): String

    external fun encryptAES(key: String?, value: String?, mode: String?): String

    external fun decodeAES(key: String?, value: String?, mode: String?): String

    external fun encryptRSA(value: String?, delimiter: String?): String

    external fun decodeRSA(value: String?, delimiter: String?): String

    external fun md5(value: String?): String

//    init {
//        System.loadLibrary("roselle")
//    }
}