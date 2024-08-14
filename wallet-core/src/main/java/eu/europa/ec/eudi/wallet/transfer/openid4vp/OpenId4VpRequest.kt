/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.wallet.transfer.openid4vp

import eu.europa.ec.eudi.iso18013.transfer.response.Request
import eu.europa.ec.eudi.iso18013.transfer.response.SessionTranscriptBytes
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject

class OpenId4VpRequest(
    val openId4VPAuthorization: ResolvedRequestObject.OpenId4VPAuthorization,
    val sessionTranscript: SessionTranscriptBytes,
    val requestId: String? = null,
) : Request

//class OpenId4VpZkpRequest(
//    val openId4VPAuthorization: ResolvedRequestObject.OpenId4VPAuthorization,
//    val sessionTranscript: SessionTranscriptBytes,
//    val requestId: String,
//) : Request


class OpenId4VpSdJwtRequest(
    val openId4VPAuthorization: ResolvedRequestObject.OpenId4VPAuthorization,
    val requestId: String? = null,
) : Request

//class OpenId4VpSdJwtZkpRequest(
//    val openId4VPAuthorization: ResolvedRequestObject.OpenId4VPAuthorization,
//    val requestId: String,
//) : Request

