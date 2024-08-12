package eu.europa.ec.eudi.wallet.issue.openid4vci

import android.content.Context
import eu.europa.ec.eudi.wallet.util.getEncryptedSharedPreferences

object DocumentManagerSdJwt {
    private lateinit var dataStore: SdJwtDocumentDataStore

    fun init(context: Context) {
        dataStore = SdJwtDocumentDataStore(context)
    }

    fun storeDocument(id: String, credentials: String) {
        dataStore.add(id, credentials)
    }

    fun getDocumentById(id: String) = dataStore.get(id)

    fun getAllDocuments() = dataStore.getAll()
}

data class SdJwtDocument(
    val id: String,
    val vct: String,
    val docName: String,
    val requiresUserAuth: Boolean,
    val data: String,
)

private class SdJwtDocumentDataStore(
    context: Context,
) {
    private var sharedPreferences = getEncryptedSharedPreferences(context)

    fun add(id: String, credentials: String) {
        sharedPreferences.edit().putString(PREFIX_ID + id, credentials).apply()
    }

    fun get(id: String) = sharedPreferences.getString(PREFIX_ID + id, null)?.toDocument(id)

    fun getAll() = sharedPreferences.all.filter {
        it.key.startsWith(PREFIX_ID)
    }.mapNotNull {
        (it.value as? String)?.toDocument(it.key)
    }

    private companion object {
        private const val PREFIX_ID = "id:"
    }
}

private fun String.toDocument(id: String): SdJwtDocument {

    // WIP parse values from this
    val vct = "vct"
    val docName = "docName"
    val requiresUserAuth = false
    val data = this

    return SdJwtDocument(
        id = id,
        vct = vct,
        docName = docName,
        requiresUserAuth = requiresUserAuth,
        data = data,
    )
}