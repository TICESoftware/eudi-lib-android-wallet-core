package eu.europa.ec.eudi.wallet.transfer.openid4vp

import eu.europa.ec.eudi.iso18013.transfer.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.RequestedDocumentData
import eu.europa.ec.eudi.iso18013.transfer.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseGenerator

class OpenId4VpSdJwtAndMDocGenerator(
    private val mDocGenerator: OpenId4VpCBORResponseGeneratorImpl,
    private val sdJwtGenerator: OpenId4VpSdJwtResponseGeneratorImpl
) : ResponseGenerator<OpenId4VpRequest>() {

    override fun createResponse(disclosedDocuments: DisclosedDocuments): ResponseResult {
        return mDocGenerator.createResponse(disclosedDocuments)
    }

    override fun setReaderTrustStore(readerTrustStore: ReaderTrustStore): ResponseGenerator<OpenId4VpRequest> {
        return mDocGenerator.setReaderTrustStore(readerTrustStore)
    }

    override fun parseRequest(request: OpenId4VpRequest): RequestedDocumentData {
        request.openId4VPAuthorization
            .presentationDefinition
            .inputDescriptors.forEach { inputDescriptor ->
                return when (inputDescriptor.format?.json) {
                    "mso_mdoc" -> { mDocGenerator.parseRequest(request) }
                    "vc+sd-jwt" -> { sdJwtGenerator.parseRequest(request) }

                    else -> {
                        throw NotImplementedError(message = "Not supported: ${inputDescriptor.format?.json}")
                    }
                }
            }

        throw IllegalArgumentException("Empty input descriptors")
    }
}