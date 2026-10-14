---
'@owf/token-status-list': patch
'@owf/cose': patch
---

Reject a token at its `exp` instant. `verifyStatusListJwtClaims` (and so `verifyStatus`) and `CwtPayload.verifyClaims` (and so `Cwt.verify` and `StatusListCwtPayload.verifyClaims`) accepted a token when the current time was exactly `exp` plus the skew. RFC 7519 section 4.1.4 says a token MUST NOT be accepted on or after its `exp`, and RFC 8392 gives `exp` the same meaning in a CWT. This matches `@sd-jwt/core`.
