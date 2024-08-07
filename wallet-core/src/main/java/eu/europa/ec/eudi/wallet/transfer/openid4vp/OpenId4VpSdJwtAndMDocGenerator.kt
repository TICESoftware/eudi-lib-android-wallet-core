package eu.europa.ec.eudi.wallet.transfer.openid4vp

import eu.europa.ec.eudi.iso18013.transfer.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.RequestedDocumentData
import eu.europa.ec.eudi.iso18013.transfer.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import eu.europa.ec.eudi.iso18013.transfer.response.Request
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseGenerator

class OpenId4VpSdJwtAndMDocGenerator(
    private val mDocGenerator: OpenId4VpCBORResponseGeneratorImpl,
    private val sdJwtGenerator: OpenId4VpSdJwtResponseGeneratorImpl
) {

    fun createResponse(disclosedDocuments: DisclosedDocuments): ResponseResult {
        return mDocGenerator.createResponse(disclosedDocuments)
    }

    fun setReaderTrustStore(readerTrustStore: ReaderTrustStore) {
        sdJwtGenerator.setReaderTrustStore(readerTrustStore)
        mDocGenerator.setReaderTrustStore(readerTrustStore)
    }

    internal fun getOpenid4VpX509CertificateTrust() = openid4VpX509CertificateTrust


    fun parseRequest(request: Request): RequestedDocumentData {
        when (request) {
            is OpenId4VpRequest -> {
                mDocGenerator.parseRequest(request)
            }

            is OpenId4VpSdJwtRequest -> {
                sdJwtGenerator.parseRequest(request)
            }

            else -> {
                throw NotImplementedError(message = "Not supported: ${request::class.simpleName}")
            }
        }
    }
}