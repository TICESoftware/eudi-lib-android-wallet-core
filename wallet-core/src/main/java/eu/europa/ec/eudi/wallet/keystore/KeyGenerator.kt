package eu.europa.ec.eudi.wallet.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import eu.europa.ec.eudi.wallet.keystore.KeyGenerator.SigningKeyConfig
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException

private const val ANDROID_KEY_STORE = "AndroidKeyStore"
public const val DEV_KEY_ALIAS = "eudi_wallet_dev_key"

interface KeyGenerator {
    @RequiresApi(Build.VERSION_CODES.R)
    @Throws(KeyStoreException::class)
    fun getSigningKey(config: SigningKeyConfig): KeyStore.PrivateKeyEntry

    data class SigningKeyConfig(
        val keyType: Int,
        val timeoutSeconds: Int,
    )
}

internal object KeyGeneratorImpl : KeyGenerator {
    @RequiresApi(Build.VERSION_CODES.R)
    @Throws(KeyStoreException::class)
    override fun getSigningKey(config: SigningKeyConfig): KeyStore.PrivateKeyEntry {
        val entry = getKeyStoreEntry(config)
        if (entry !is KeyStore.PrivateKeyEntry) throw KeyStoreException("Entry not an instance of a PrivateKeyEntry.")
        return entry
    }

    @RequiresApi(Build.VERSION_CODES.R)
    @Throws(KeyStoreException::class)
    private fun getKeyStoreEntry(config: SigningKeyConfig) = try {
        val keyStore = getKeyStore()
        keyStore.getEntry(DEV_KEY_ALIAS, null).let {
            if (it == null) {
                generateKey(config)
                keyStore.getEntry(DEV_KEY_ALIAS, null)!!
            } else {
                it
            }
        }
    } catch (exception: KeyStoreException) {
        throw KeyStoreException("Get KeyStore entry failed.", exception)
    } catch (exception: NoSuchAlgorithmException) {
        throw KeyStoreException("Get KeyStore entry failed.", exception)
    } catch (exception: UnrecoverableEntryException) {
        throw KeyStoreException("Get KeyStore entry failed.", exception)
    } catch (exception: NoSuchProviderException) {
        throw KeyStoreException("Get KeyStore entry failed.", exception)
    } catch (exception: InvalidAlgorithmParameterException) {
        throw KeyStoreException("Get KeyStore entry failed.", exception)
    }

    @Throws(KeyStoreException::class)
    public fun getKeyStore(): KeyStore = try {
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
    } catch (exception: KeyStoreException) {
        throw KeyStoreException("Get KeyStore instance failed.", exception)
    } catch (exception: CertificateException) {
        throw KeyStoreException("Get KeyStore instance failed.", exception)
    } catch (exception: IOException) {
        throw KeyStoreException("Get KeyStore instance failed.", exception)
    } catch (exception: NoSuchAlgorithmException) {
        throw KeyStoreException("Get KeyStore instance failed.", exception)
    }

    @RequiresApi(Build.VERSION_CODES.R)
    @Throws(KeyStoreException::class)
    private fun generateKey(config: SigningKeyConfig) {
        val keyPairGenerator: KeyPairGenerator =
            try {
                KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    ANDROID_KEY_STORE
                )
            } catch (exception: NoSuchAlgorithmException) {
                throw KeyStoreException("Generate key failed.", exception)
            } catch (exception: NoSuchProviderException) {
                throw KeyStoreException("Generate key failed.", exception)
            }
        val parameterSpec: KeyGenParameterSpec =
            KeyGenParameterSpec
                .Builder(
                    DEV_KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN,
                ).run {
                    setUserAuthenticationParameters(config.timeoutSeconds, config.keyType)
                    setUserAuthenticationRequired(true)
                    setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    build()
                }

        try {
            keyPairGenerator.initialize(parameterSpec)
        } catch (exception: InvalidAlgorithmParameterException) {
            throw KeyStoreException("Generate key failed.", exception)
        }
        keyPairGenerator.generateKeyPair()
    }
}