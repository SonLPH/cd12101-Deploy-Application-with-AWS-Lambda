import { decode } from 'jsonwebtoken'
import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../utils/logger.mjs'

const logger = createLogger('utils')
/**
 * Parse a JWT token and return a user id
 * @param jwtToken JWT token to parse
 * @returns a user id from the JWT token
 */
export function parseUserId(jwtToken) {
  const decodedJwt = decode(jwtToken)
  return decodedJwt.sub
}

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJAn7ULfq0T46rMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi0weTV4MjZmNDU1ZXFrd3ZlLnVzLmF1dGgwLmNvbTAeFw0yNDEwMjkx
NzIxNTNaFw0zODA3MDgxNzIxNTNaMCwxKjAoBgNVBAMTIWRldi0weTV4MjZmNDU1
ZXFrd3ZlLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAL2sVJ3ZJeAliVHbwVa66CKnDR1YGXhSJdWryRD6F9olyycvEjA2Cw3xFGgn
mLbtwZIYCx9Q5jyUJJZ4mC+0TA2SUuHf6wa3kAxEFAv6qirJRf3y5X+nzKoJ9fkf
pHg/NPu768cWdW5kxRw5RhFOLniPWz9u59Jd6t/qjjH1W6ctSTYSHPe0XDKRmOcr
t8JV1a8bElU7ZdSOpy/QTVkPsWmHyo5AHWofj8o0wnedwEVwCLYViGyaBO5pmKQ/
32xSPiwL6BBElZU+hTAyymioYcSxjn+USnrCrY2vV1PdGAoxmT2T+6Ot85tQwVv5
dJEuhyyx58GEV1X+KX4KyTXpbBMCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUriKEcscIty0Jix/RDC10UZdBSLEwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQBYv7ynXEJwtB1IAJO/f8oMvd5mGJMTYvxM+Lm/Rq28
TZhpj6KiqnfGiGqRVjciWpHXG4BBHExL+Jvjlr//+ZGr/vvCQ3i3NsrTv5p4f8FE
M1zYqASyZNc8kgQUCncTK0umXkY7YGw0py1YYHayRP2FjMQouVUeoU5xvH1HJQmU
Co0auOpYTTMY8liS95HciJDYJHphGyeVBr2LooS4KxdCv4ycLchJNEQxroks3i+U
Zih9J+u1y0WmZHUv78IMzCT9oyy8pzySkdfEUjORdjnwTr5reVsOuR2BD7FDjsyB
DQG4xymm9mW6Fq9WjUcTGKfKg0PvmMk7pnD+PrGa90R9
-----END CERTIFICATE-----`

const jwksUrl = 'https://test-endpoint.auth0.com/.well-known/jwks.json'

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  return jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
