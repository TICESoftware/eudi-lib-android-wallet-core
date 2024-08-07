package eu.europa.ec.eudi.wallet.transfer.openid4vp

import android.content.Context
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.storage.AndroidStorageEngine
import com.android.identity.storage.StorageEngine
import eu.europa.ec.eudi.iso18013.transfer.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.DocumentsResolver
import eu.europa.ec.eudi.iso18013.transfer.RequestedDocumentData
import eu.europa.ec.eudi.iso18013.transfer.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import eu.europa.ec.eudi.iso18013.transfer.response.Request
import eu.europa.ec.eudi.wallet.logging.Logger

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

    class Builder(context: Context) {
        private val _context = context.applicationContext
        var documentsResolver: DocumentsResolver? = null
        var readerTrustStore: ReaderTrustStore? = null
        var logger: Logger? = null

        /**
         * Reader trust store that will be used to validate the certificate chain of the mdoc verifier
         *
         * @param readerTrustStore
         */
        fun readerTrustStore(readerTrustStore: ReaderTrustStore) =
            apply { this.readerTrustStore = readerTrustStore }

        fun build(): OpenId4VpSdJwtAndMDocGenerator {
            return documentsResolver?.let { documentsResolver ->
                val openId4VpCBORResponseGeneratorImpl = OpenId4VpCBORResponseGeneratorImpl(
                    documentsResolver,
                    storageEngine,
                    androidSecureArea,
                    logger
                ).apply {
                    readerTrustStore?.let { setReaderTrustStore(it) }
                }

                val openId4VpSdJwtResponseGeneratorImpl = OpenId4VpSdJwtResponseGeneratorImpl(
                    documentsResolver,
                    storageEngine,
                    androidSecureArea,
                    logger
                ).apply {
                    readerTrustStore?.let { setReaderTrustStore(it) }
                }

                OpenId4VpSdJwtAndMDocGenerator(
                    openId4VpCBORResponseGeneratorImpl,
                    openId4VpSdJwtResponseGeneratorImpl
                ).apply {
                    readerTrustStore?.let { setReaderTrustStore(it) }
                }
            } ?: throw IllegalArgumentException("documentResolver not set")
        }

        private val storageEngine: StorageEngine
            get() = AndroidStorageEngine.Builder(_context, _context.noBackupFilesDir)
                .setUseEncryption(true)
                .build()
        private val androidSecureArea: AndroidKeystoreSecureArea
            get() = AndroidKeystoreSecureArea(_context, storageEngine)
    }
}