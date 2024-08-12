package eu.europa.ec.eudi.wallet.issue.openid4vci

import android.content.Context
import eu.europa.ec.eudi.wallet.util.getEncryptedSharedPreferences
import org.json.JSONException
import org.json.JSONObject
import java.util.Base64

object DocumentManagerSdJwt {
    private lateinit var dataStore: SdJwtDocumentDataStore

    fun init(context: Context, requiresUserAuth: Boolean) {
        dataStore = SdJwtDocumentDataStore(context, requiresUserAuth)
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
    val requiresUserAuth: Boolean,
) {
    private var sharedPreferences = getEncryptedSharedPreferences(context)

    fun add(id: String, credentials: String) {
        sharedPreferences.edit().putString(PREFIX_ID + id, credentials).apply()
    }

    fun get(id: String) = sharedPreferences.getString(PREFIX_ID + id, null)?.toDocument(id, requiresUserAuth)

    fun getAll() = sharedPreferences.all.filter {
        it.key.startsWith(PREFIX_ID)
    }.mapNotNull {
        (it.value as? String)?.toDocument(it.key, requiresUserAuth)
    }

    private companion object {
        private const val PREFIX_ID = "id:"
    }
}

private fun String.toDocument(
    id: String,
    requiresUserAuth: Boolean,
) = try {
    val payloadString = split(".")[1]
    val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(payloadString)))

    val vct = payloadJson.getString("vct")
    val docName = "Personalausweis"
    val data = payloadJson.toString()

    SdJwtDocument(
        id = id,
        vct = vct,
        docName = docName,
        requiresUserAuth = requiresUserAuth,
        data = data,
    )
} catch (_: JSONException) {
    null
}