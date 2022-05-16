package com.pizzk.keystore.app

import android.app.Application
import com.pizzk.keystore.KeyStore

class MainApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        val path = "file:///android_asset/certs/config"
        val signature = "43D85434D6B289502C36147C6E914132FDE1C2AB"
        KeyStore.init(path, "debug", signature)
    }
}