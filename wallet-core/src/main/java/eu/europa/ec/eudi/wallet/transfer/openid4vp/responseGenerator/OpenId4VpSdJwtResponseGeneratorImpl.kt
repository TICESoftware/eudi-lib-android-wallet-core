package eu.europa.ec.eudi.wallet.transfer.openid4vp.responseGenerator

import android.os.Build
import android.security.keystore.KeyProperties
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.iso18013.transfer.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.DocItem
import eu.europa.ec.eudi.iso18013.transfer.DocRequest
import eu.europa.ec.eudi.iso18013.transfer.DocumentsResolver
import eu.europa.ec.eudi.iso18013.transfer.ReaderAuth
import eu.europa.ec.eudi.iso18013.transfer.RequestDocument
import eu.europa.ec.eudi.iso18013.transfer.RequestedDocumentData
import eu.europa.ec.eudi.iso18013.transfer.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import eu.europa.ec.eudi.iso18013.transfer.response.DeviceResponse
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseGenerator
import eu.europa.ec.eudi.openid4vp.legalName
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.JsonPointer
import eu.europa.ec.eudi.sdjwt.JwtAndClaims
import eu.europa.ec.eudi.sdjwt.KeyBindingSigner
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtVerifier
import eu.europa.ec.eudi.sdjwt.asJwtVerifier
import eu.europa.ec.eudi.sdjwt.present
import eu.europa.ec.eudi.sdjwt.serializeWithKeyBinding
import eu.europa.ec.eudi.wallet.internal.Openid4VpX509CertificateTrust
import eu.europa.ec.eudi.wallet.issue.openid4vci.DocumentManagerSdJwt
import eu.europa.ec.eudi.wallet.issue.openid4vci.pem
import eu.europa.ec.eudi.wallet.keystore.DEV_KEY_ALIAS
import eu.europa.ec.eudi.wallet.keystore.KeyGenerator
import eu.europa.ec.eudi.wallet.keystore.KeyGeneratorImpl
import eu.europa.ec.eudi.wallet.transfer.openid4vp.OpenId4VpSdJwtRequest
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

class OpenId4VpSdJwtResponseGeneratorImpl(
    private val documentsResolver: DocumentsResolver,
) : ResponseGenerator<OpenId4VpSdJwtRequest>() {
    private var readerTrustStore: ReaderTrustStore? = null
    private val openid4VpX509CertificateTrust = Openid4VpX509CertificateTrust(readerTrustStore)

    override fun createResponse(disclosedDocuments: DisclosedDocuments) = runBlocking {
        val disclosedDocument = disclosedDocuments.documents.first()

        val credentials = DocumentManagerSdJwt.getDocumentById(disclosedDocument.documentId)?.data
                          ?: throw IllegalArgumentException()

        val sdJwt = getSdJwtFromCredentials(credentials)

        val jsonPointer = disclosedDocument.docRequest.requestItems.mapNotNull { item ->
            JsonPointer.parse(item.elementIdentifier)
        }.toSet()

        val presentationSdJwt = sdJwt.present(jsonPointer)

        val key = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            KeyGeneratorImpl.getSigningKey(KeyGenerator.SigningKeyConfig(KeyProperties.AUTH_DEVICE_CREDENTIAL, 60))
        } else {
            throw Exception()
        }

        val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        val certificate =
            certificateFactory.generateCertificate(ByteArrayInputStream(key.certificate.encoded)) as X509Certificate
        val ecKey = ECKey.parse(certificate)

        val string = presentationSdJwt!!.serializeWithKeyBinding(
            jwtSerializer = { it.first },
            hashAlgorithm = HashAlgorithm.SHA_256,
            keyBindingSigner = object : KeyBindingSigner {
                override val signAlgorithm: JWSAlgorithm = JWSAlgorithm.ES256
                override val publicKey: AsymmetricJWK = ecKey.toPublicJWK()
                override fun getJCAContext(): JCAContext = JCAContext()
                @Throws(java.security.SignatureException::class)
                override fun sign(p0: JWSHeader?, p1: ByteArray?): Base64URL =
                    Base64URL(KeyGeneratorImpl.sign(key.privateKey, p1 ?: ByteArray(0)))
            },
            claimSetBuilderAction = { }
        )

        return@runBlocking ResponseResult.Success(DeviceResponse(string.toByteArray()))
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
                    inputDescriptor.format?.json?.contains("vc_sd_jwt") == true
                }

        if (inputDescriptors.isEmpty()) {
            throw IllegalArgumentException()
        }

        val namespace = "eu.europa.ec.eudi.pid.1"

        val requestedFields = inputDescriptors.associate { inputDescriptor ->
            inputDescriptor.id.value.trim() to inputDescriptor.constraints.fields()
                .map { fieldConstraint ->
                    val elementIdentifier = fieldConstraint.paths.first().value
                        .replace(".", "/")
                        .drop(1)

                    namespace to elementIdentifier
                }.groupBy({ it.first }, { it.second })
                .mapValues { (_, values) -> values.toList() }
                .toMap()
        }

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

    private suspend fun getSdJwtFromCredentials(credentials: String): SdJwt.Issuance<JwtAndClaims> {
        val headerString = credentials.split(".").first()
        val headerJson = JSONObject(String(Base64.getUrlDecoder().decode(headerString)))
        val keyString = headerJson.getJSONArray("x5c").getString(0).replace("\n", "")
        println(keyString)

        val pemString = "-----BEGIN CERTIFICATE-----\n" +
                        "${keyString}\n" +
                        "-----END CERTIFICATE-----"

        val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        val certificate =
            certificateFactory.generateCertificate(ByteArrayInputStream(pemString.toByteArray())) as X509Certificate

        val ecKey = ECKey.parse(certificate)
        val jwtSignatureVerifier = ECDSAVerifier(ecKey).asJwtVerifier()

        return SdJwtVerifier.verifyIssuance(
            jwtSignatureVerifier,
            credentials
        ).getOrThrow()
    }
}