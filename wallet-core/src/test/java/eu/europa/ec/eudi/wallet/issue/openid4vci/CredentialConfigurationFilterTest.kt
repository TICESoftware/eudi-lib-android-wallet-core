/*
 *  Copyright (c) 2024 European Commission
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

package eu.europa.ec.eudi.wallet.issue.openid4vci

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vci.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.ProofTypeMeta
import eu.europa.ec.eudi.openid4vci.ProofTypesSupported
import eu.europa.ec.eudi.openid4vci.SdJwtVcCredential
import eu.europa.ec.eudi.wallet.issue.openid4vci.CredentialConfigurationFilter.Companion.DocTypeFilter
import eu.europa.ec.eudi.wallet.issue.openid4vci.CredentialConfigurationFilter.Companion.MsoMdocFormatFilter
import eu.europa.ec.eudi.wallet.issue.openid4vci.CredentialConfigurationFilter.Companion.ProofTypeFilter
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager.Config.ProofType
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialConfigurationFilterTest {

    @Test
    fun `FormatFilter returns true for MsoMdocCredential`() {
        val credentialConfiguration = mockk<MsoMdocCredential>(relaxed = true)
        assertTrue(MsoMdocFormatFilter(credentialConfiguration))
    }

    @Test
    fun `FormatFilter returns false for non-MsoMdocCredential`() {
        val credentialConfiguration = mockk<SdJwtVcCredential>(relaxed = true)
        assertFalse(MsoMdocFormatFilter(credentialConfiguration))
    }


    @Test
    fun `ProofTypeFilter returns true for supported proof type`() {
        val credentialConfiguration = mockk<MsoMdocCredential>(relaxed = true)
        every { credentialConfiguration.proofTypesSupported } returns ProofTypesSupported(
            setOf(
                ProofTypeMeta.Jwt(listOf(JWSAlgorithm.ES256))
            )
        )

        assertTrue(ProofTypeFilter(ProofType.JWT)(credentialConfiguration))
    }

    @Test
    fun `ProofTypeFilter returns false for supported proof type but unsupported algorithm`() {
        val credentialConfiguration = mockk<MsoMdocCredential>(relaxed = true)
        every { credentialConfiguration.proofTypesSupported } returns ProofTypesSupported(
            setOf(
                ProofTypeMeta.Jwt(listOf(JWSAlgorithm.ES384))
            )
        )

        assertFalse(ProofTypeFilter(ProofType.CWT)(credentialConfiguration))
    }

    @Test
    fun `ProofTypeFilter returns false for unsupported proof type`() {
        val credentialConfiguration = mockk<MsoMdocCredential>(relaxed = true)
        every { credentialConfiguration.proofTypesSupported } returns ProofTypesSupported(
            setOf(
                ProofTypeMeta.LdpVp
            )
        )

        assertFalse(ProofTypeFilter(ProofType.JWT)(credentialConfiguration))
    }

    @Test
    fun `ProofTypeFilter returns false for empty proof types`() {
        val credentialConfiguration = mockk<MsoMdocCredential>(relaxed = true)
        every { credentialConfiguration.proofTypesSupported } returns ProofTypesSupported.Empty

        assertFalse(ProofTypeFilter(ProofType.JWT)(credentialConfiguration))
    }

    @Test
    fun `DocTypeFilterFactory returns true for matching docType`() {
        val docType = "testDocType"
        val credentialConfiguration = mockk<MsoMdocCredential>(relaxed = true)
        every { credentialConfiguration.docType } returns docType

        assertTrue(DocTypeFilter(docType).invoke(credentialConfiguration))
    }

    @Test
    fun `DocTypeFilterFactory returns false for non-matching docType`() {
        val docType = "testDocType"
        val credentialConfiguration = mockk<MsoMdocCredential>(relaxed = true)
        every { credentialConfiguration.docType } returns "differentDocType"

        assertFalse(DocTypeFilter(docType).invoke(credentialConfiguration))
    }
}