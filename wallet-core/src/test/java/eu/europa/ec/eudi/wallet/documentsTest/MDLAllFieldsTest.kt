/*
 *  Copyright (c) 2023-2024 European Commission
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package eu.europa.ec.eudi.wallet.documentsTest

import co.nstant.`in`.cbor.model.MajorType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.iso18013.transfer.DisclosedDocument
import eu.europa.ec.eudi.iso18013.transfer.DisclosedDocuments
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtDigest
import eu.europa.ec.eudi.sdjwt.SdJwtFactory
import eu.europa.ec.eudi.sdjwt.SdJwtIssuer
import eu.europa.ec.eudi.sdjwt.SdJwtVerifier
import eu.europa.ec.eudi.sdjwt.asJwtVerifier
import eu.europa.ec.eudi.sdjwt.nimbus
import eu.europa.ec.eudi.sdjwt.serialize
import eu.europa.ec.eudi.sdjwt.serializeWithKeyBinding
import eu.europa.ec.eudi.wallet.documentsTest.util.BaseTest
import eu.europa.ec.eudi.wallet.documentsTest.util.CBORTestUtil
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.ADMINISTRATIVE_NUMBER
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.AGE_BIRTH_YEAR
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.AGE_IN_YEARS
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.AGE_OVER_15
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.AGE_OVER_18
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.AGE_OVER_21
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.AGE_OVER_60
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.AGE_OVER_65
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.AGE_OVER_68
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.BIRTH_DATE
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.BIRTH_PLACE
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.DOCUMENT_NUMBER
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.DRIVING_PRIVILEGES
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.EXPIRY_DATE
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.EYE_COLOUR
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.FAMILY_NAME
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.FAMILY_NAME_NATIONAL_CHARACTER
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.GIVEN_NAME
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.GIVEN_NAME_NATIONAL_CHARACTER
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.HAIR_COLOUR
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.HEIGHT
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.ISSUE_DATE
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.ISSUING_AUTHORITY
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.ISSUING_COUNTRY
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.ISSUING_JURISDICTION
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.NATIONALITY
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.PORTRAIT
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.PORTRAIT_CAPTURE_DATE
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.RESIDENT_ADDRESS
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.RESIDENT_CITY
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.RESIDENT_COUNTRY
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.RESIDENT_POSTAL_CODE
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.RESIDENT_STATE
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.SEX
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.SIGNATURE_USUAL_MARK
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.UN_DISTINGUISHING_SIGN
import eu.europa.ec.eudi.wallet.documentsTest.util.Constants.WEIGHT
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Locale


class MDLAllFieldsTest : BaseTest() {

    @BeforeEach
    override fun setUp() {
        super.setUp()
    }

    @Test
    fun `family_name is valid`() {
        testUnicodeStringMDLField(FAMILY_NAME)
    }

    @Test
    fun `given_name is valid`() {
        testUnicodeStringMDLField(GIVEN_NAME)
    }

    @Test
    fun `birth_date is valid`() {
        testFullDateMDLField(BIRTH_DATE)
    }

    @Test
    fun `issue_date is valid`() {
        testTDateOrFullDateMDLField(ISSUE_DATE)
    }

    @Test
    fun `expiry_date is valid`() {
        testTDateOrFullDateMDLField(EXPIRY_DATE)
    }

    @Test
    fun `issuing_country is valid`() {
        testUnicodeStringMDLField(ISSUING_COUNTRY)
    }

    @Test
    fun `issuing_authority is valid`() {
        testUnicodeStringMDLField(ISSUING_AUTHORITY)
    }

    @Test
    fun `document_number is valid`() {
        testUnicodeStringMDLField(DOCUMENT_NUMBER)
    }

    @Test
    fun `portrait is valid`() {
        testByteStringMdlField(PORTRAIT)
    }

    @Test
    fun `driving_privileges is valid`() {
        testMDLField(DRIVING_PRIVILEGES)
    }

    @Test
    fun `un_distinguishing_sign is valid`() {
        testUnicodeStringMDLField(UN_DISTINGUISHING_SIGN)
    }

    @Test
    fun `administrative_number is valid`() {
        testUnicodeStringMDLField(ADMINISTRATIVE_NUMBER)
    }

    @Test
    fun `sex is valid`() {
        val field = SEX
        val value = testNumMDLField(field).toInt()
        assert(value == 0 || value == 1 || value == 2 || value == 9)
    }

    @Test
    fun `height is valid`() {
        testNumMDLField(HEIGHT)
    }

    @Test
    fun `weight is valid`() {
        testNumMDLField(WEIGHT)
    }

    @Test
    fun `eye_colour is valid`() {
        val raw = testMDLField(EYE_COLOUR)

        val validColors = arrayOf(
            "black", "blue",
            "brown", "dichromatic", "grey", "green",
            "hazel", "maroon", "pink", "unknown"
        )
        val dataValue = CBORTestUtil.getStringValue(raw!!)

        assert(validColors.contains(dataValue))
    }

    @Test
    fun `hair_colour is valid`() {
        val raw = testMDLField(HAIR_COLOUR, MajorType.UNICODE_STRING)

        val validColors = arrayOf(
            "bald", "black",
            "blond", "brown", "grey", "red", "auburn",
            "sandy", "white", "unknown"
        )
        val dataValue = CBORTestUtil.getStringValue(raw!!)

        assert(validColors.contains(dataValue))
    }

    @Test
    fun `birth_place is valid`() {
        testUnicodeStringMDLField(BIRTH_PLACE)
    }

    @Test
    fun `resident_address is valid`() {
        testUnicodeStringMDLField(RESIDENT_ADDRESS)
    }

    @Test
    fun `portrait_capture_date is valid`() {
        testTDateOrFullDateMDLField(PORTRAIT_CAPTURE_DATE)
    }

    @Test
    fun `signature_usual_mark is valid`() {
        testByteStringMdlField(SIGNATURE_USUAL_MARK)
    }

    @Test
    fun `age_in_years is valid`() {
        testNumMDLField(AGE_IN_YEARS)
    }

    @Test
    fun `age_birth_year is valid`() {
        testNumMDLField(AGE_BIRTH_YEAR)
    }

    @Test
    fun `issuing_jurisdiction is valid`() {
        testUnicodeStringMDLField(ISSUING_JURISDICTION)
    }

    @Test
    fun `nationality is valid`() {
        val countryCodes = Locale.getISOCountries()
        val countryCode = testUnicodeStringMDLField(NATIONALITY)
        assert(countryCodes.contains(countryCode))
    }

    @Test
    fun `resident_city is valid`() {
        testUnicodeStringMDLField(RESIDENT_CITY)
    }

    @Test
    fun `resident_state is valid`() {
        testUnicodeStringMDLField(RESIDENT_STATE)
    }

    @Test
    fun `resident_postal_code is valid`() {
        testUnicodeStringMDLField(RESIDENT_POSTAL_CODE)
    }

    @Test
    fun `resident_country is valid`() {
        testUnicodeStringMDLField(RESIDENT_COUNTRY)
    }

    @Test
    fun `family_name_national_character is valid`() {
        testUnicodeStringMDLField(FAMILY_NAME_NATIONAL_CHARACTER)
    }

    @Test
    fun `given_name_national_character is valid`() {
        testUnicodeStringMDLField(GIVEN_NAME_NATIONAL_CHARACTER)
    }

    @Test
    fun `age_over_15 is valid`() {
        testBooleanMDLField(AGE_OVER_15)
    }

    @Test
    fun `age_over_18 is valid`() {
        testBooleanMDLField(AGE_OVER_18)
    }

    @Test
    fun `age_over_21 is valid`() {
        testBooleanMDLField(AGE_OVER_21)
    }

    @Test
    fun `age_over_60 is valid`() {
        testBooleanMDLField(AGE_OVER_60)
    }

    @Test
    fun `age_over_65 is valid`() {
        testBooleanMDLField(AGE_OVER_65)
    }

    @Test
    fun `age_over_68 is valid`() {
        testBooleanMDLField(AGE_OVER_68)
    }

    private val credentialString =
        """eyJ4NWMiOlsiTUlJQ2REQ0NBaHVnQXdJQkFnSUJBakFLQmdncWhrak9QUVFEQWpDQmlERUxNQWtHQTFVRUJoTUNSRVV4RHpBTkJnTlZCQWNNQmtKbGNteHBiakVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneEVUQVBCZ05WQkFzTUNGUWdRMU1nU1VSRk1UWXdOQVlEVlFRRERDMVRVRkpKVGtRZ1JuVnVhMlVnUlZWRVNTQlhZV3hzWlhRZ1VISnZkRzkwZVhCbElFbHpjM1ZwYm1jZ1EwRXdIaGNOTWpRd05UTXhNRGd4TXpFM1doY05NalV3TnpBMU1EZ3hNekUzV2pCc01Rc3dDUVlEVlFRR0V3SkVSVEVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneENqQUlCZ05WQkFzTUFVa3hNakF3QmdOVkJBTU1LVk5RVWtsT1JDQkdkVzVyWlNCRlZVUkpJRmRoYkd4bGRDQlFjbTkwYjNSNWNHVWdTWE56ZFdWeU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU9GQnE0WU1LZzR3NWZUaWZzeXR3QnVKZi83RTdWaFJQWGlObTUyUzNxMUVUSWdCZFh5REsza1Z4R3hnZUhQaXZMUDN1dU12UzZpREVjN3FNeG12ZHVLT0JrRENCalRBZEJnTlZIUTRFRmdRVWlQaENrTEVyRFhQTFcyL0owV1ZlZ2h5dyttSXdEQVlEVlIwVEFRSC9CQUl3QURBT0JnTlZIUThCQWY4RUJBTUNCNEF3TFFZRFZSMFJCQ1l3SklJaVpHVnRieTV3YVdRdGFYTnpkV1Z5TG1KMWJtUmxjMlJ5ZFdOclpYSmxhUzVrWlRBZkJnTlZIU01FR0RBV2dCVFVWaGpBaVRqb0RsaUVHTWwyWXIrcnU4V1F2akFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUFiZjVUemtjUXpoZldvSW95aTFWTjdkOEk5QnNGS20xTVdsdVJwaDJieUdRSWdLWWtkck5mMnhYUGpWU2JqVy9VLzVTNXZBRUM1WHhjT2FudXNPQnJvQmJVPSIsIk1JSUNlVENDQWlDZ0F3SUJBZ0lVQjVFOVFWWnRtVVljRHRDaktCL0gzVlF2NzJnd0NnWUlLb1pJemowRUF3SXdnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUI0WERUSTBNRFV6TVRBMk5EZ3dPVm9YRFRNME1EVXlPVEEyTkRnd09Wb3dnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWUd6ZHdGRG5jNytLbjVpYkF2Q09NOGtlNzdWUXhxZk1jd1pMOElhSUErV0NST2NDZm1ZL2dpSDkycU1ydTVwL2t5T2l2RTBSQy9JYmRNT052RG9VeWFObU1HUXdIUVlEVlIwT0JCWUVGTlJXR01DSk9PZ09XSVFZeVhaaXY2dTd4WkMrTUI4R0ExVWRJd1FZTUJhQUZOUldHTUNKT09nT1dJUVl5WFppdjZ1N3haQytNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3RGdZRFZSMFBBUUgvQkFRREFnR0dNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJR0VtN3drWktIdC9hdGI0TWRGblhXNnlybndNVVQydTEzNmdkdGwxMFk2aEFpQnVURnF2Vll0aDFyYnh6Q1AweFdaSG1RSzlrVnl4bjhHUGZYMjdFSXp6c3c9PSJdLCJraWQiOiJNSUdVTUlHT3BJR0xNSUdJTVFzd0NRWURWUVFHRXdKRVJURVBNQTBHQTFVRUJ3d0dRbVZ5YkdsdU1SMHdHd1lEVlFRS0RCUkNkVzVrWlhOa2NuVmphMlZ5WldrZ1IyMWlTREVSTUE4R0ExVUVDd3dJVkNCRFV5QkpSRVV4TmpBMEJnTlZCQU1NTFZOUVVrbE9SQ0JHZFc1clpTQkZWVVJKSUZkaGJHeGxkQ0JRY205MGIzUjVjR1VnU1hOemRXbHVaeUJEUVFJQkFnPT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJwbGFjZV9vZl9iaXJ0aCI6eyJfc2QiOlsiUDZiLUxnTk9fRUlpNm5ubmRCbW1wS1FIdDVvTlBpLVVsWldGRmU4VnFDMCJdfSwiX3NkIjpbIi1sOFBnZ2hLdEFmZUFwZXRDOEZGS0lfcGFlVkV4bmY4dFpJZzZCQ205TlkiLCJDSEhVb1JySFhIbXNvbHVEbEtqMWF1X3RmTEVKUmYzUUszVzFLZkVXYUlZIiwiQ1cwbVBFblFMMnhZYWxEbXBRLS11Vkg5bEM1cG1MU1JEeTdjblRBU0FfNCIsIkd5dEtxYzM0SHM2UjAtTEpMWVNYOUJVSGloZi1kbmtoYV9KM1NlQWN2M0EiLCJOZGZkeEJWY0Q4Smo5MHIyUUxFamhvMkpDTjRPWWRxeG1KcGs0S1hmVlp3IiwiZDJjNDdxZ3pGR1lDR194dFFYYVNEeEdueWpwZXFrRk16bV92MDVERjFOSSIsIm1zVW1QVEE4ZE1rRFRvam43cm5waFEzRnpjN3k4NkptT1NkX2NaWWdKQXMiXSwiYWRkcmVzcyI6eyJfc2QiOlsiQ2ZtTlY3WVNfMURod3NIUi1scWRScXAtT1NETFpVS2FBR3F3eHhMdzZTOCIsIkt0VjdoblFuNXdINVlIYXBfajhXX3BmMlJnV2x1LWZFSTd6VTNLOWo4NGsiLCJid19TVUtCWERnVDVYdE04Z1l3OFVvY05pV0JTNDN3T1lXazZGMjZQRlY0IiwiekRSTndDMkV0UUZoaWVpRmJtUEtiYy1ISU5nZnZ6SnpGSi1qUFdhOHdtMCJdfSwiaXNzdWluZ19jb3VudHJ5IjoiREUiLCJ2Y3QiOiJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiLCJpc3N1aW5nX2F1dGhvcml0eSI6IkRFIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwczovL2RlbW8ucGlkLWlzc3Vlci5idW5kZXNkcnVja2VyZWkuZGUvYyIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJUZVdfdEJIM01KM3M4RHA3NE1oMWtWdUNvWURMaGlIMW56dFcxVnVUcEpRIiwieSI6IkdtRFVXQXVibmQxbHlnUEJSX1ZvVUt0YkR6SEYtNFBma3daQjhwMnU4SUEifX0sImV4cCI6MTcyMzYxNjc1MSwiaWF0IjoxNzIyNDA3MTUxLCJhZ2VfZXF1YWxfb3Jfb3ZlciI6eyJfc2QiOlsiM1pqTUJkM1pRbThGYzFtQmwtZC1PLVFJaTA3YkpjY3lzNDlqaFlPNVJVYyIsIjY3YVN5dzJGenVaQjVJZXV6Q1V1VXNuVml5T3owUDBCckdQMzFhbGtCbjAiLCJDZkQ1MEstcHRwaXpGQnB2cE8yWFhyaVFfRzdWcGIxRDB3bGdjUHpUSlQ0IiwiSW1qU0I2Z2lhMDhZeXhRUFBfcXp5d1FFamcwU254R1ZxWlVfTl9FVFl2SSIsIlExZ1ZOSWtIYWU0ZGdmY2RoSUwwTEZIckdSX3dBZUpRT0ZwbTljbXBaREUiLCJYY290cHIzV3Q5U21jUjZDSzhtMlBPRE5zRXBDWnRRelZGT1N3UnJ5QXMwIl19fQ.xqQyzeKALOWVnmJBx7BjH8YBdwu-5H51f6dkUkXsp2BcwUDUvo-ni4NVo3cB9FKf-eoCU4e_jJIuYr5o-S003w~WyJHV3JoVGVzaDE4Y191aEgtR01ORFJ3IiwiZmFtaWx5X25hbWUiLCJNVVNURVJNQU5OIl0~WyJaZGRMRzhBd0dDWTF3Sm9qWmkweEpBIiwiZ2l2ZW5fbmFtZSIsIkVSSUtBIl0~WyJIWHVBd3JXaXVBT01hN0JfZ2ZVZlhnIiwiYmlydGhkYXRlIiwiMTk4NC0wMS0yNiJd~WyJFcVAtNnY5eVdZOGdKSmItMFVLMUh3IiwiYWdlX2JpcnRoX3llYXIiLDE5ODRd~WyJEMTdfUGxGdHlDVml0V3JvaTJ5bEtRIiwiYWdlX2luX3llYXJzIiw0MF0~WyJiMkp3ZjZhakN1eXoyWmxfUDd3bnZ3IiwiYmlydGhfZmFtaWx5X25hbWUiLCJHQUJMRVIiXQ~WyJBUzZNRjJrZFVBdmQ5S1p0Wnl3N1FnIiwibmF0aW9uYWxpdGllcyIsWyJERSJdXQ~WyJFWmVrOFMxMUlBNUZwVG1Iem1mTW5BIiwiMTIiLHRydWVd~WyJLcEdrWW85SzA2NThyZnVyZHJPLUJRIiwiMTQiLHRydWVd~WyJqQkRBVzdsWWRrUVNvRUV2c2hfMm1BIiwiMTYiLHRydWVd~WyItTUc3M3hwNUhnOHpBRFVaNU9lN1B3IiwiMTgiLHRydWVd~WyJiMGNwT0ZxT0lVeW53cDdma0ZoN3RRIiwiMjEiLHRydWVd~WyJZS3o1SUZPQk5mZHc4R2JhU3l1TlJ3IiwiNjUiLGZhbHNlXQ~WyJMNHY3ajc1N2poS1BPX2xtTmMxQ0dnIiwibG9jYWxpdHkiLCJCRVJMSU4iXQ~WyJIVEVzdmZpZEtBTXV2aFdFbW9DN25nIiwibG9jYWxpdHkiLCJLw5ZMTiJd~WyJfWDMtalZFMWdkWWlTNmY0RGhFU3V3IiwiY291bnRyeSIsIkRFIl0~WyI5b1huQTNBM01PWGZhbV9jdzZ5N1ZBIiwicG9zdGFsX2NvZGUiLCI1MTE0NyJd~WyJGNzNmMThYSnpWbzYtbG1tTzJoUnBnIiwic3RyZWV0X2FkZHJlc3MiLCJIRUlERVNUUkFTU0UgMTciXQ~"""

    @Test
    fun someCoolTest(): Unit = runBlocking {
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

        val presentationSdJwt = SdJwt.Presentation(verifiedIssuanceSdJwt.jwt, verifiedIssuanceSdJwt.disclosures)

        val temp = presentationSdJwt.serializeWithKeyBinding() {  }

        println("$temp")
    }
}
