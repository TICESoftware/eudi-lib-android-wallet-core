package eu.europa.ec.eudi.wallet.transfer.openid4vp.responseGenerator

import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.storage.StorageEngine
import eu.europa.ec.eudi.iso18013.transfer.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.DocItem
import eu.europa.ec.eudi.iso18013.transfer.DocRequest
import eu.europa.ec.eudi.iso18013.transfer.DocumentsResolver
import eu.europa.ec.eudi.iso18013.transfer.ReaderAuth
import eu.europa.ec.eudi.iso18013.transfer.RequestDocument
import eu.europa.ec.eudi.iso18013.transfer.RequestedDocumentData
import eu.europa.ec.eudi.iso18013.transfer.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseGenerator
import eu.europa.ec.eudi.iso18013.transfer.response.SessionTranscriptBytes
import eu.europa.ec.eudi.openid4vp.legalName
import eu.europa.ec.eudi.wallet.internal.Openid4VpX509CertificateTrust
import eu.europa.ec.eudi.wallet.logging.Logger
import eu.europa.ec.eudi.wallet.transfer.openid4vp.OpenId4VpSdJwtRequest

class OpenId4VpSdJwtResponseGeneratorImpl(
    private val documentsResolver: DocumentsResolver,
    private val storageEngine: StorageEngine,
    private val secureArea: AndroidKeystoreSecureArea,
    private val logger: Logger? = null
) : ResponseGenerator<OpenId4VpSdJwtRequest>() {
    private var readerTrustStore: ReaderTrustStore? = null
    private val openid4VpX509CertificateTrust = Openid4VpX509CertificateTrust(readerTrustStore)
    private var sessionTranscript: SessionTranscriptBytes? = null

    override fun createResponse(disclosedDocuments: DisclosedDocuments): ResponseResult {
        TODO("Not yet implemented")
    }

    override fun setReaderTrustStore(readerTrustStore: ReaderTrustStore) = apply {
        openid4VpX509CertificateTrust.setReaderTrustStore(readerTrustStore)
        this.readerTrustStore = readerTrustStore
    }

    internal fun getOpenid4VpX509CertificateTrust() = openid4VpX509CertificateTrust

    override fun parseRequest(request: OpenId4VpSdJwtRequest): RequestedDocumentData {
        val inputDescriptors =
            request.openId4VPAuthorization.presentationDefinition.inputDescriptors
                .filter { inputDescriptor ->
                    inputDescriptor.format?.json?.contains("vc+sd-jwt") == true
                }

        if (inputDescriptors.isEmpty()) {
            throw IllegalArgumentException()
        }

        val namespace = "eu.europa.ec.eudi.pid.1" //TODO - FIND NAMESPACE!!!

        val requestedFields = inputDescriptors.map { inputDescriptor ->
            inputDescriptor.id.value.trim() to inputDescriptor.constraints.fields()
                .mapNotNull { fieldConstraint ->
                    val path = fieldConstraint.paths.first().value
                    Regex("\\[\"\\$\\.(.*?)\"\\]").find(path)
                        ?.let { matchResult ->
                            val elementIdentifier = matchResult.value
                            if (elementIdentifier.isNotBlank()) {
                                namespace to elementIdentifier
                            } else {
                                null
                            }
                        }

                }.groupBy({ it.first }, { it.second })
                .mapValues { (_, values) -> values.toList() }
                .toMap()
        }.toMap()

        val readerAuth = openid4VpX509CertificateTrust.getTrustResult()?.let { (chain, isTrusted) ->
            ReaderAuth(
                byteArrayOf(0),
                true, /* It is always true as siop-openid4vp library validates it internally and returns a fail status */
                chain,
                isTrusted,
                request.openId4VPAuthorization.client.legalName() ?: "",
            )
        }

        return createRequestedDocumentData(requestedFields, readerAuth)
    }

    private fun createRequestedDocumentData(
        requestedFields: Map<String, Map<String, List<String>>>,
        readerAuth: ReaderAuth?,
    ): RequestedDocumentData {
        val requestedDocuments = mutableListOf<RequestDocument>()
        requestedFields.forEach { document ->
            // create doc item
            val docItems = mutableListOf<DocItem>()
            document.value.forEach { (namespace, elementIds) ->
                elementIds.forEach { elementId ->
                    docItems.add(DocItem(namespace, elementId))
                }
            }
            val docType = document.key

            requestedDocuments.addAll(
                documentsResolver.resolveDocuments(
                    DocRequest(
                        docType,
                        docItems,
                        readerAuth
                    )
                )
            )
        }
        return RequestedDocumentData(requestedDocuments)
    }
}