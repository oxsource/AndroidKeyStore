package com.pizzk.keystore

import android.content.Context
import java.io.File
import java.io.FileOutputStream

object KeyStoreAssets {
    private const val NAMESPACE = "KeyStore"
    private const val DELIMITERS = "::"
    private const val CONFIG = "config"
    private const val P12 = "p12"
    private const val X509 = "x509"

    fun init(context: Context) {
        Thread {
            val name = "certs/config"
            val signature = "43D85434D6B289502C36147C6E914132FDE1C2AB"
            val file = copy(context, name)
            KeyStore.init(file.absolutePath, "debug", signature)
        }.start()
    }

    private fun copy(context: Context, path: String): File {
        val dir = File(context.filesDir, NAMESPACE)
        if (!dir.exists()) dir.mkdirs()
        val config = File(dir, CONFIG)
        if (config.exists() && config.length() > 0) return config
        val lines: MutableList<String> = mutableListOf()
        kotlin.runCatching {
            context.assets.open(path).reader().useLines { lines.addAll(it) }
            val items = lines.mapNotNull { s -> parse(context, dir, s) }
            if (items.isEmpty()) throw Exception("parse config result is empty.")
            val value = items.joinToString(separator = "\n")
            if (config.exists()) config.delete()
            FileOutputStream(config).bufferedWriter().use { outs ->
                outs.write(value)
                outs.flush()
            }
        }.onFailure { it.printStackTrace() }
        return config
    }

    private fun parse(context: Context, dir: File, line: String): String? {
        val splits = line.split(DELIMITERS)
        val key = splits.getOrNull(0) ?: return null
        val value = splits.getOrNull(1) ?: return null
        if (key.isEmpty() || value.isEmpty()) return null
        return when (key) {
            P12, X509 -> {
                val name = File(value).name
                val file = File(dir, name)
                if (file.exists()) file.delete()
                context.assets.open(value).copyTo(FileOutputStream(file))
                arrayOf(key, file.absolutePath).joinToString(separator = DELIMITERS)
            }
            else -> line
        }
    }
}