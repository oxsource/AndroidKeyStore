package com.pizzk.keystore.app

import android.app.Application
import com.pizzk.keystore.KeyStoreAssets

class MainApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        KeyStoreAssets.init(this)
    }
}