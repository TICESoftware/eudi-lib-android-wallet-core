package eu.europa.ec.eudi.wallet.issue.openid4vci

object DocumentManagerSdJwt {
    private lateinit var dataStore: SdJwtDocumentDataStore

    fun getDocumentById(id: String): SdJwtDocument? {
        return dataStore.get(id)
    }

    fun getAllDocuments(): List<SdJwtDocument> {
        return dataStore.getAll()
    }

    fun storeDocument(id: String, credential: String) {
        dataStore.add(id, credential)
    }
}

data class SdJwtDocument(
    val id: String,
    val vct: String,
    val docName: String,
    val requiresUserAuth: Boolean,
    val data: String,
)

private class SdJwtDocumentDataStore {
    private val documents = mutableMapOf<String, SdJwtDocument>()

    fun add(id: String, credential: String) {
        documents[id] = credential.toDocument(id)
    }

    fun get(id: String): SdJwtDocument? {
        return documents[id]
    }

    fun getAll(): List<SdJwtDocument> {
        return documents.values.toList()
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