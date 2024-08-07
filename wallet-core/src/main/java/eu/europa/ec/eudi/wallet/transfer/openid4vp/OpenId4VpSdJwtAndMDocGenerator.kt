package eu.europa.ec.eudi.wallet.transfer.openid4vp

import eu.europa.ec.eudi.iso18013.transfer.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.RequestedDocumentData
import eu.europa.ec.eudi.iso18013.transfer.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import eu.europa.ec.eudi.iso18013.transfer.response.Request

class OpenId4VpSdJwtAndMDocGenerator(
    private val mDocGenerator: OpenId4VpCBORResponseGeneratorImpl,
    private val sdJwtGenerator: OpenId4VpSdJwtResponseGeneratorImpl
) {
    private enum class FormatState {
        Cbor,
        SdJwt
    }

    private var formatState: FormatState = FormatState.Cbor

    fun createResponse(disclosedDocuments: DisclosedDocuments): ResponseResult {
        return when (formatState) {
            FormatState.Cbor -> mDocGenerator.createResponse(disclosedDocuments)
            FormatState.SdJwt -> sdJwtGenerator.createResponse(disclosedDocuments)
        }
    }

    fun setReaderTrustStore(readerTrustStore: ReaderTrustStore) {
        sdJwtGenerator.setReaderTrustStore(readerTrustStore)
        mDocGenerator.setReaderTrustStore(readerTrustStore)
    }

    internal fun getOpenid4VpX509CertificateTrust() = when (formatState) {
        FormatState.Cbor -> mDocGenerator.getOpenid4VpX509CertificateTrust()
        FormatState.SdJwt -> sdJwtGenerator.getOpenid4VpX509CertificateTrust()
    }


    fun parseRequest(request: Request): RequestedDocumentData {
        return when (request) {
            is OpenId4VpRequest -> {
                formatState = FormatState.Cbor
                mDocGenerator.parseRequest(request)
            }

            is OpenId4VpSdJwtRequest -> {
                formatState = FormatState.SdJwt
                sdJwtGenerator.parseRequest(request)
            }

            else -> {
                throw NotImplementedError(message = "Not supported: ${request::class.simpleName}")
            }
        }
    }
}