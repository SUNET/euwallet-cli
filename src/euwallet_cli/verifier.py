# the first:
# unecrypted


# POST https://example-verifier.com/callback
# Content-Type: application/x-www-form-urlencoded

# vp_token=eyJhbGciOiJFUzI1NiIsImtpZCI6InIzZ2Q4ZXBoIn0.eyJpc3MiOiJodHRwczovL2FwcC53YWxsZXQuY29tIiwic3ViIjoidXNlcklkIiwidnBfaGFzaCI6InNka2oiLCJ2aF9jbGFpbXMiOnsic29tZUF0dHIiOiJ2YWx1ZSJ9fQ.GdIoVKojlS...
# &presentation_submission=%7B%22id%22%3A%22123abc%22%2C%22definition_id%22%3A%22def123%22%2C%22descriptor_map%22%3A%5B%7B%22id%22%3A%22driver_license%22%2C%22path%22%3A%22%24%22%7D%5D%7D
# &state=4ad3b177

# ---- the second:

# encrypted

# and the second case is the encrypted version in which vp token presentation submission and state is all put into one jwe string and being put in a filed "response"
# the second case is chosen when the response_Mode is DIRECT_POST_JWT and the verifier has indicated it wants an encrypted response by providing authorization_encrypted_response_alg
# and a public key in S.client_metadata.jwks

import json

from cryptojwt import jwe, jwk


def generate_response(
    response_mode, verifier_metadata, vp_token, presentation_submission, state
):
    """
    Generate the response to the verifier depending on response_mode.

    If response_mode == 'DIRECT_POST_JWT' and verifier provided encryption info,
    then response is a single JWE string with vp_token, presentation_submission, and state,
    put under field "response".

    Otherwise, response is separate tokens in plain JSON.
    """

    if (
        response_mode == "DIRECT_POST_JWT"
        and "authorization_encrypted_response_alg" in verifier_metadata
        and "jwks" in verifier_metadata
    ):

        # Combine values into one payload
        payload = {
            "vp_token": vp_token,
            "presentation_submission": presentation_submission,
            "state": state,
        }

        # Convert payload to string
        plaintext = json.dumps(payload)

        # Load the verifier's public key
        keyset = jwk.JWKSet()
        keyset.import_keyset(json.dumps(verifier_metadata["jwks"]))
        # Assuming first key is the intended encryption key
        public_key = keyset["keys"][0]

        jwe_token = jwe.JWE(
            plaintext.encode("utf-8"),
            protected={
                "alg": verifier_metadata["authorization_encrypted_response_alg"],
                "enc": "A256GCM",
            },
        )
        jwe_token.add_recipient(jwk.JWK(**public_key))

        encrypted_response = jwe_token.serialize(compact=True)

        return {"response": encrypted_response}

    else:
        # Plain response with separate fields
        return {
            "vp_token": vp_token,
            "presentation_submission": presentation_submission,
            "state": state,
        }


"""
{'given_name': 'Charlize',
 'family_name': 'Theron',
 'birth_date': '1988-12-11',
 'issuing_authority': 'EU',
 'issuing_country': 'EU',
 'vct': 'urn:eu.europa.ec.eudi:pid:1',
 'nationality': ['EU'],
 'birth_place': 'EU',
 'issuance_date': '2025-03-24',
 'expiry_date': '2026-03-24',
 'iss': 'https://satosa-test-1.sunet.se',
 'iat': 1742832862,
 'exp': 1774368862,
 'cnf': {'jwk': {'kty': 'EC',
                 'use': 'sig',
                 'kid': 'V0hZd3hvY0F3LVF2RVJQWHUwYUFIVXRYaDZYc1AzcXpqWjlSWGdxNDFwTQ',
                 'crv': 'P-256',
                 'x': 'ZlB4jy20kGUCL1paFcZ93XndwDxlWpZ_tIbt1W6qCkA',
                 'y': '2kM0ifDVlSVr4iiNNhHkess6wJoeF1Q01RSNuTiEntU'}}}
"""
