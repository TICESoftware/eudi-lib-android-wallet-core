package eu.europa.ec.eudi.wallet.transfer.openid4vp.responseGenerator

import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.storage.StorageEngine
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
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
import eu.europa.ec.eudi.iso18013.transfer.response.SessionTranscriptBytes
import eu.europa.ec.eudi.openid4vp.legalName
import eu.europa.ec.eudi.sdjwt.JsonPointer
import eu.europa.ec.eudi.sdjwt.JwtAndClaims
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtVerifier
import eu.europa.ec.eudi.sdjwt.asJwtVerifier
import eu.europa.ec.eudi.sdjwt.present
import eu.europa.ec.eudi.wallet.internal.Openid4VpX509CertificateTrust
import eu.europa.ec.eudi.wallet.logging.Logger
import eu.europa.ec.eudi.wallet.transfer.openid4vp.OpenId4VpSdJwtRequest
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

class OpenId4VpSdJwtResponseGeneratorImpl(
    private val documentsResolver: DocumentsResolver,
    private val storageEngine: StorageEngine,
    private val secureArea: AndroidKeystoreSecureArea,
    private val logger: Logger? = null
) : ResponseGenerator<OpenId4VpSdJwtRequest>() {
    private var readerTrustStore: ReaderTrustStore? = null
    private val openid4VpX509CertificateTrust = Openid4VpX509CertificateTrust(readerTrustStore)
    private var sessionTranscript: SessionTranscriptBytes? = null

    data class SdJwtResponse(
        val value: String
    ) : eu.europa.ec.eudi.iso18013.transfer.response.Response

    override fun createResponse(disclosedDocuments: DisclosedDocuments) = runBlocking {
        val disclosedDocument = disclosedDocuments.documents.first()

        val sdJwt = getSdJwt() //TODO get sdjwt from disclosedDocument

        val jsonPointer = disclosedDocument.docRequest.requestItems.mapNotNull { item ->
            JsonPointer.parse(item.elementIdentifier)
        }.toSet()

        val presentationSdJwt = sdJwt.present(jsonPointer)

//            val string = presentationSdJwt.serializeWithKeyBinding(
//                jwtSerializer = { it.first },
//                hashAlgorithm = HashAlgorithm.SHA_256,
//                keyBindingSigner = object: KeyBindingSigner {
//                    override val signAlgorithm: JWSAlgorithm = JWSAlgorithm.ES256
//                    override val publicKey: AsymmetricJWK = holderKey.toPublicJWK()
//                    override fun getJCAContext(): JCAContext = actualSigner.jcaContext
//                    override fun sign(p0: JWSHeader?, p1: ByteArray?): Base64URL = actualSigner.sign(p0, p1)
//                },
//                claimSetBuilderAction = {  }
//            )

        return@runBlocking ResponseResult.Success(DeviceResponse("".toByteArray()))
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

        val namespace = "eu.europa.ec.eudi.pid.1" //TODO - FIND NAMESPACE!!!

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

    private val credentialString =
        """eyJ4NWMiOlsiTUlJQ2REQ0NBaHVnQXdJQkFnSUJBakFLQmdncWhrak9QUVFEQWpDQmlERUxNQWtHQTFVRUJoTUNSRVV4RHpBTkJnTlZCQWNNQmtKbGNteHBiakVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneEVUQVBCZ05WQkFzTUNGUWdRMU1nU1VSRk1UWXdOQVlEVlFRRERDMVRVRkpKVGtRZ1JuVnVhMlVnUlZWRVNTQlhZV3hzWlhRZ1VISnZkRzkwZVhCbElFbHpjM1ZwYm1jZ1EwRXdIaGNOTWpRd05UTXhNRGd4TXpFM1doY05NalV3TnpBMU1EZ3hNekUzV2pCc01Rc3dDUVlEVlFRR0V3SkVSVEVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneENqQUlCZ05WQkFzTUFVa3hNakF3QmdOVkJBTU1LVk5RVWtsT1JDQkdkVzVyWlNCRlZVUkpJRmRoYkd4bGRDQlFjbTkwYjNSNWNHVWdTWE56ZFdWeU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU9GQnE0WU1LZzR3NWZUaWZzeXR3QnVKZi83RTdWaFJQWGlObTUyUzNxMUVUSWdCZFh5REsza1Z4R3hnZUhQaXZMUDN1dU12UzZpREVjN3FNeG12ZHVLT0JrRENCalRBZEJnTlZIUTRFRmdRVWlQaENrTEVyRFhQTFcyL0owV1ZlZ2h5dyttSXdEQVlEVlIwVEFRSC9CQUl3QURBT0JnTlZIUThCQWY4RUJBTUNCNEF3TFFZRFZSMFJCQ1l3SklJaVpHVnRieTV3YVdRdGFYTnpkV1Z5TG1KMWJtUmxjMlJ5ZFdOclpYSmxhUzVrWlRBZkJnTlZIU01FR0RBV2dCVFVWaGpBaVRqb0RsaUVHTWwyWXIrcnU4V1F2akFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUFiZjVUemtjUXpoZldvSW95aTFWTjdkOEk5QnNGS20xTVdsdVJwaDJieUdRSWdLWWtkck5mMnhYUGpWU2JqVy9VLzVTNXZBRUM1WHhjT2FudXNPQnJvQmJVPSIsIk1JSUNlVENDQWlDZ0F3SUJBZ0lVQjVFOVFWWnRtVVljRHRDaktCL0gzVlF2NzJnd0NnWUlLb1pJemowRUF3SXdnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUI0WERUSTBNRFV6TVRBMk5EZ3dPVm9YRFRNME1EVXlPVEEyTkRnd09Wb3dnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWUd6ZHdGRG5jNytLbjVpYkF2Q09NOGtlNzdWUXhxZk1jd1pMOElhSUErV0NST2NDZm1ZL2dpSDkycU1ydTVwL2t5T2l2RTBSQy9JYmRNT052RG9VeWFObU1HUXdIUVlEVlIwT0JCWUVGTlJXR01DSk9PZ09XSVFZeVhaaXY2dTd4WkMrTUI4R0ExVWRJd1FZTUJhQUZOUldHTUNKT09nT1dJUVl5WFppdjZ1N3haQytNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3RGdZRFZSMFBBUUgvQkFRREFnR0dNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJR0VtN3drWktIdC9hdGI0TWRGblhXNnlybndNVVQydTEzNmdkdGwxMFk2aEFpQnVURnF2Vll0aDFyYnh6Q1AweFdaSG1RSzlrVnl4bjhHUGZYMjdFSXp6c3c9PSJdLCJraWQiOiJNSUdVTUlHT3BJR0xNSUdJTVFzd0NRWURWUVFHRXdKRVJURVBNQTBHQTFVRUJ3d0dRbVZ5YkdsdU1SMHdHd1lEVlFRS0RCUkNkVzVrWlhOa2NuVmphMlZ5WldrZ1IyMWlTREVSTUE4R0ExVUVDd3dJVkNCRFV5QkpSRVV4TmpBMEJnTlZCQU1NTFZOUVVrbE9SQ0JHZFc1clpTQkZWVVJKSUZkaGJHeGxkQ0JRY205MGIzUjVjR1VnU1hOemRXbHVaeUJEUVFJQkFnPT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJwbGFjZV9vZl9iaXJ0aCI6eyJfc2QiOlsiUDZiLUxnTk9fRUlpNm5ubmRCbW1wS1FIdDVvTlBpLVVsWldGRmU4VnFDMCJdfSwiX3NkIjpbIi1sOFBnZ2hLdEFmZUFwZXRDOEZGS0lfcGFlVkV4bmY4dFpJZzZCQ205TlkiLCJDSEhVb1JySFhIbXNvbHVEbEtqMWF1X3RmTEVKUmYzUUszVzFLZkVXYUlZIiwiQ1cwbVBFblFMMnhZYWxEbXBRLS11Vkg5bEM1cG1MU1JEeTdjblRBU0FfNCIsIkd5dEtxYzM0SHM2UjAtTEpMWVNYOUJVSGloZi1kbmtoYV9KM1NlQWN2M0EiLCJOZGZkeEJWY0Q4Smo5MHIyUUxFamhvMkpDTjRPWWRxeG1KcGs0S1hmVlp3IiwiZDJjNDdxZ3pGR1lDR194dFFYYVNEeEdueWpwZXFrRk16bV92MDVERjFOSSIsIm1zVW1QVEE4ZE1rRFRvam43cm5waFEzRnpjN3k4NkptT1NkX2NaWWdKQXMiXSwiYWRkcmVzcyI6eyJfc2QiOlsiQ2ZtTlY3WVNfMURod3NIUi1scWRScXAtT1NETFpVS2FBR3F3eHhMdzZTOCIsIkt0VjdoblFuNXdINVlIYXBfajhXX3BmMlJnV2x1LWZFSTd6VTNLOWo4NGsiLCJid19TVUtCWERnVDVYdE04Z1l3OFVvY05pV0JTNDN3T1lXazZGMjZQRlY0IiwiekRSTndDMkV0UUZoaWVpRmJtUEtiYy1ISU5nZnZ6SnpGSi1qUFdhOHdtMCJdfSwiaXNzdWluZ19jb3VudHJ5IjoiREUiLCJ2Y3QiOiJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiLCJpc3N1aW5nX2F1dGhvcml0eSI6IkRFIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwczovL2RlbW8ucGlkLWlzc3Vlci5idW5kZXNkcnVja2VyZWkuZGUvYyIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJUZVdfdEJIM01KM3M4RHA3NE1oMWtWdUNvWURMaGlIMW56dFcxVnVUcEpRIiwieSI6IkdtRFVXQXVibmQxbHlnUEJSX1ZvVUt0YkR6SEYtNFBma3daQjhwMnU4SUEifX0sImV4cCI6MTcyMzYxNjc1MSwiaWF0IjoxNzIyNDA3MTUxLCJhZ2VfZXF1YWxfb3Jfb3ZlciI6eyJfc2QiOlsiM1pqTUJkM1pRbThGYzFtQmwtZC1PLVFJaTA3YkpjY3lzNDlqaFlPNVJVYyIsIjY3YVN5dzJGenVaQjVJZXV6Q1V1VXNuVml5T3owUDBCckdQMzFhbGtCbjAiLCJDZkQ1MEstcHRwaXpGQnB2cE8yWFhyaVFfRzdWcGIxRDB3bGdjUHpUSlQ0IiwiSW1qU0I2Z2lhMDhZeXhRUFBfcXp5d1FFamcwU254R1ZxWlVfTl9FVFl2SSIsIlExZ1ZOSWtIYWU0ZGdmY2RoSUwwTEZIckdSX3dBZUpRT0ZwbTljbXBaREUiLCJYY290cHIzV3Q5U21jUjZDSzhtMlBPRE5zRXBDWnRRelZGT1N3UnJ5QXMwIl19fQ.xqQyzeKALOWVnmJBx7BjH8YBdwu-5H51f6dkUkXsp2BcwUDUvo-ni4NVo3cB9FKf-eoCU4e_jJIuYr5o-S003w~WyJHV3JoVGVzaDE4Y191aEgtR01ORFJ3IiwiZmFtaWx5X25hbWUiLCJNVVNURVJNQU5OIl0~WyJaZGRMRzhBd0dDWTF3Sm9qWmkweEpBIiwiZ2l2ZW5fbmFtZSIsIkVSSUtBIl0~WyJIWHVBd3JXaXVBT01hN0JfZ2ZVZlhnIiwiYmlydGhkYXRlIiwiMTk4NC0wMS0yNiJd~WyJFcVAtNnY5eVdZOGdKSmItMFVLMUh3IiwiYWdlX2JpcnRoX3llYXIiLDE5ODRd~WyJEMTdfUGxGdHlDVml0V3JvaTJ5bEtRIiwiYWdlX2luX3llYXJzIiw0MF0~WyJiMkp3ZjZhakN1eXoyWmxfUDd3bnZ3IiwiYmlydGhfZmFtaWx5X25hbWUiLCJHQUJMRVIiXQ~WyJBUzZNRjJrZFVBdmQ5S1p0Wnl3N1FnIiwibmF0aW9uYWxpdGllcyIsWyJERSJdXQ~WyJFWmVrOFMxMUlBNUZwVG1Iem1mTW5BIiwiMTIiLHRydWVd~WyJLcEdrWW85SzA2NThyZnVyZHJPLUJRIiwiMTQiLHRydWVd~WyJqQkRBVzdsWWRrUVNvRUV2c2hfMm1BIiwiMTYiLHRydWVd~WyItTUc3M3hwNUhnOHpBRFVaNU9lN1B3IiwiMTgiLHRydWVd~WyJiMGNwT0ZxT0lVeW53cDdma0ZoN3RRIiwiMjEiLHRydWVd~WyJZS3o1SUZPQk5mZHc4R2JhU3l1TlJ3IiwiNjUiLGZhbHNlXQ~WyJMNHY3ajc1N2poS1BPX2xtTmMxQ0dnIiwibG9jYWxpdHkiLCJCRVJMSU4iXQ~WyJIVEVzdmZpZEtBTXV2aFdFbW9DN25nIiwibG9jYWxpdHkiLCJLw5ZMTiJd~WyJfWDMtalZFMWdkWWlTNmY0RGhFU3V3IiwiY291bnRyeSIsIkRFIl0~WyI5b1huQTNBM01PWGZhbV9jdzZ5N1ZBIiwicG9zdGFsX2NvZGUiLCI1MTE0NyJd~WyJGNzNmMThYSnpWbzYtbG1tTzJoUnBnIiwic3RyZWV0X2FkZHJlc3MiLCJIRUlERVNUUkFTU0UgMTciXQ~"""

    private suspend fun getSdJwt(): SdJwt.Issuance<JwtAndClaims> {
        val headerString = credentialString.split(".").first()
        val headerJson = JSONObject(String(Base64.getUrlDecoder().decode(headerString)))
        val keyString = headerJson.getJSONArray("x5c").getString(0).replace("\n", "")
        println(keyString)

        val key2 = "-----BEGIN CERTIFICATE-----\n" +
                "${keyString}\n" +
                "-----END CERTIFICATE-----"

        val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        val certificate =
            certificateFactory.generateCertificate(ByteArrayInputStream(key2.toByteArray())) as X509Certificate

        val ecKey = ECKey.parse(certificate)
        val jwtSignatureVerifier = ECDSAVerifier(ecKey).asJwtVerifier()

        val verifiedIssuanceSdJwt = SdJwtVerifier.verifyIssuance(
            jwtSignatureVerifier,
            credentialString
        ).getOrThrow()

        return verifiedIssuanceSdJwt
    }
}