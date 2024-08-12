package eu.europa.ec.eudi.wallet.util

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import javax.crypto.AEADBadTagException

private const val PREF_FILE_NAME = "secure_prefs"

@Throws(java.security.GeneralSecurityException::class, java.io.IOException::class)
fun getEncryptedSharedPreferences(context: Context): SharedPreferences {
    val masterKey: MasterKey = MasterKey
        .Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    return try {
        createEncryptedSharedPreferences(context, masterKey)
    } catch (e: AEADBadTagException) {
        clearEncryptedSharedPreferences(context)
        createEncryptedSharedPreferences(context, masterKey)
    }
}

@Throws(java.security.GeneralSecurityException::class, java.io.IOException::class)
private fun createEncryptedSharedPreferences(
    context: Context,
    masterKey: MasterKey,
) = EncryptedSharedPreferences.create(
    context,
    PREF_FILE_NAME,
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

private fun clearEncryptedSharedPreferences(context: Context) {
    context.getSharedPreferences(PREF_FILE_NAME, Context.MODE_PRIVATE).edit().clear().apply()
}