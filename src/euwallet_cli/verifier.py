#!/usr/bin/env python3
import base64
import json
import time
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptojwt.jwk import ec, x509
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar

"""
x5c is needed in the verifier’s request because the 
verifier may be outside the federation, and the JWT 
header must be self-contained? (trying to understand 
the role of the x5c in the header for the bigger 
picture
"""
# ---- the first:
# unecrypted

"""
├── vp_token (JWT)
│   ├── payload
│   │   ├── verifiableCredential: ...
│   │   ├── cnf:
│   │   │   └── jwk: {}
│   │   └── ...
├── presentation_submission
└── state
"""
# POST https://example-verifier.com/callback
# Content-Type: application/x-www-form-urlencoded
# response_type

# vp_token=eyJhbGciOiJFUzI1NiIsImtpZCI6InIzZ2Q4ZXBoIn0.eyJpc3MiOiJodHRwczovL2FwcC53YWxsZXQuY29tIiwic3ViIjoidXNlcklkIiwidnBfaGFzaCI6InNka2oiLCJ2aF9jbGFpbXMiOnsic29tZUF0dHIiOiJ2YWx1ZSJ9fQ.GdIoVKojlS...
# &presentation_submission=%7B%22id%22%3A%22123abc%22%2C%22definition_id%22%3A%22def123%22%2C%22descriptor_map%22%3A%5B%7B%22id%22%3A%22driver_license%22%2C%22path%22%3A%22%24%22%7D%5D%7D
# &state=4ad3b177
# vp_token the authorization details

# ---- the second:

# encrypted
# response_mode=direct_post.jwt: the second case is the encrypted version in which vp token presentation submission and state is all put into one jwe string and being put in a filed "response"
# the second case is chosen when the response_Mode is DIRECT_POST_JWT and the verifier has indicated it wants an encrypted response by providing authorization_encrypted_response_alg
# and a public key in S.client_metadata.jwks
# response_mode=direct_post.jwt wraps the whole response into one JWT
# TODO: may be better if presentation defenition fetched from presentation_definition_uri: Optional
# autherization response
# token response
token_in_qr_code = (
    """
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDVHpDQ0FmYWdBd0lCQWdJUkFPU2w2dVc5R1VaK240ZGhRa3V6NXJvd0NnWUlLb1pJemowRUF3SXdmakVMTUFrR0ExVUVCaE1DVTBVeEVqQVFCZ05WQkFjVENWTjBiMk5yYUc5c2JURU9NQXdHQTFVRUNoTUZVMVZPUlZReEhEQWFCZ05WQkFNVEUzWmpkbVZ5YVdacFpYSXVjM1Z1WlhRdWMyVXhMVEFyQmdOVkJBVVRKRGc0WVdReU9HSTJMVE5qTm1JdE5HVTNaUzFoWkRSbUxUVTFNbU15WkRVd01UQTVZVEFlRncweU5UQXpNalV4TWpJeE1EaGFGdzB5TlRBek1qVXhNekl4TURoYU1INHhDekFKQmdOVkJBWVRBbE5GTVJJd0VBWURWUVFIRXdsVGRHOWphMmh2YkcweERqQU1CZ05WQkFvVEJWTlZUa1ZVTVJ3d0dnWURWUVFERXhOMlkzWmxjbWxtYVdWeUxuTjFibVYwTG5ObE1TMHdLd1lEVlFRRkV5UTRPR0ZrTWpoaU5pMHpZelppTFRSbE4yVXRZV1EwWmkwMU5USmpNbVExTURFd09XRXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUnpFM1VvUGpoVHQyQlRDLytYdzBPOU1EdzRZRERHbUJGQUNpdGhFZzlMWUF6UFlKRFU4SjNZdnZYR09ZdWJwbGtRbmNhUUhGWGFVUElYS2RjaUpTanlvMVV3VXpBT0JnTlZIUThCQWY4RUJBTUNBNmd3RXdZRFZSMGxCQXd3Q2dZSUt3WUJCUVVIQXdFd0RBWURWUjBUQVFIL0JBSXdBREFlQmdOVkhSRUVGekFWZ2hOMlkzWmxjbWxtYVdWeUxuTjFibVYwTG5ObE1Bb0dDQ3FHU000OUJBTUNBMGNBTUVRQ0lGWVFINGQ4alY0WExickNXRGIxdVZzcFFBY1hjOW1uUGhONEJmOTg4SVZhQWlCUyt6Vzg3LzQ4dzNrWFNGa2Z2aHJPYjY2bURreHo1OWJxYitBUHIzK3oyUT09Il19.eyJpc3MiOiJ2Y3ZlcmlmaWVyLnN1bmV0LnNlIiwic3ViIjoidG9kb19zZXRfc3ViX3ZhbHVlX2hlcmUiLCJhdWQiOlsiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92MiJdLCJleHAiOjE3NDI5MDU1NjgsIm5iZiI6MTc0MjkwNTI4NCwiaWF0IjoxNzQyOTA1Mjg0LCJqdGkiOiI5MjI2Zjc0NS0wZjUyLTQ1OGMtOTA5OC1jN2EwY2M2NGNmNmQiLCJyZXNwb25zZV91cmkiOiJodHRwOi8vMTcyLjE2LjUwLjY6ODA4MC9jYWxsYmFjay8xOWU4OGI4Yi1lOTkxLTQxYzktODUzMS0yYmJiYzNkYmNlZjgvajVva0VvVUt1UGdwZVpoLUUyM3NkcnJ1Nk5XZ25NZTJkV2FIZUVBaFpnWSIsImNsaWVudF9pZF9zY2hlbWUiOiJ4NTA5X3Nhbl9kbnMiLCJjbGllbnRfaWQiOiJ2Y3ZlcmlmaWVyLnN1bmV0LnNlIiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsInN0YXRlIjoiYmMxZmVjNzMtZWUyMi00MDVkLTljMGUtMDhjZTI5ZGI3Nzk2Iiwibm9uY2UiOiJGS2xNMlpWWmQ0aDJFcGhaREFwRUhwXzFaa3ZHU0s1UGxDQXZpZ3BzTnpJIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiJWQ0V1cm9wZWFuSGVhbHRoSW5zdXJhbmNlQ2FyZCIsInRpdGxlIjoiVkMgRUhJQyIsImRlc2NyaXB0aW9uIjoiUmVxdWlyZWQgRmllbGRzOiBWQyB0eXBlLCBTU04sIEdpdmVuIE5hbWUsIEZhbWlseSBOYW1lLCBCaXJ0aGRhdGUiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJWQ0VISUMiLCJmb3JtYXQiOnsidmMrc2Qtand0Ijp7ImFsZyI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sibmFtZSI6IlZDIHR5cGUiLCJwYXRoIjpbIiQudmN0Il0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiZW51bSI6WyJodHRwczovL3ZjLWludGVyb3AtMS5zdW5ldC5zZS9jcmVkZW50aWFsL2VoaWMvMS4wIiwiaHR0cHM6Ly92Yy1pbnRlcm9wLTIuc3VuZXQuc2UvY3JlZGVudGlhbC9laGljLzEuMCIsImh0dHBzOi8vc2F0b3NhLXRlc3QtMS5zdW5ldC5zZS9jcmVkZW50aWFsL2VoaWMvMS4wIiwiaHR0cHM6Ly9zYXRvc2EtdGVzdC0yLnN1bmV0LnNlL2NyZWRlbnRpYWwvZWhpYy8xLjAiLCJodHRwczovL3NhdG9zYS1kZXYtMS5zdW5ldC5zZS9jcmVkZW50aWFsL2VoaWMvMS4wIiwiaHR0cHM6Ly9zYXRvc2EtZGV2LTIuc3VuZXQuc2UvY3JlZGVudGlhbC9laGljLzEuMCIsIkVISUNDcmVkZW50aWFsIl19fSx7Im5hbWUiOiJTdWJqZWN0IiwicGF0aCI6WyIkLnN1YmplY3QiXSwiZmlsdGVyIjp7InR5cGUiOiIifX0seyJuYW1lIjoiR2l2ZW4gTmFtZSIsInBhdGgiOlsiJC5zdWJqZWN0LmZvcmVuYW1lIl0sImZpbHRlciI6eyJ0eXBlIjoiIn19LHsibmFtZSI6IkZhbWlseSBOYW1lIiwicGF0aCI6WyIkLnN1YmplY3QuZmFtaWx5X25hbWUiXSwiZmlsdGVyIjp7InR5cGUiOiIifX0seyJuYW1lIjoiQmlydGhkYXRlIiwicGF0aCI6WyIkLnN1YmplY3QuZGF0ZV9vZl9iaXJ0aCJdLCJmaWx0ZXIiOnsidHlwZSI6IiJ9fSx7Im5hbWUiOiJTU04iLCJwYXRoIjpbIiQuc29jaWFsX3NlY3VyaXR5X3BpbiJdLCJmaWx0ZXIiOnsidHlwZSI6IiJ9fSx7Im5hbWUiOiJEb2N1bWVudCBJRCIsInBhdGgiOlsiJC5kb2N1bWVudF9pZCJdLCJmaWx0ZXIiOnsidHlwZSI6IiJ9fV19fV19fQ.bS5sPMLqQB9eSMmxcXAbIFn4-bMbnRE7rMs1WOlN4AbN5uDCNbEL1L4jvl7bWcf6Phf2tczmpI-t_bNlQCLsJw
"""
).replace("\n", "")

# import json

# from cryptojwt import jwe, jwk


# def generate_response(
#     response_mode, verifier_metadata, vp_token, presentation_submission, state
# ):
#     """
#     Generate the response to the verifier depending on response_mode.

#     If response_mode == 'DIRECT_POST_JWT' and verifier provided encryption info,
#     then response is a single JWE string with vp_token, presentation_submission, and state,
#     put under field "response".

#     Otherwise, response is separate tokens in plain JSON.
#     """

#     if (
#         response_mode == "DIRECT_POST_JWT"
#         and "authorization_encrypted_response_alg" in verifier_metadata
#         and "jwks" in verifier_metadata
#     ):

#         # Combine values into one payload
#         payload = {
#             "vp_token": vp_token,
#             "presentation_submission": presentation_submission,
#             "state": state,
#         }

#         # Convert payload to string
#         plaintext = json.dumps(payload)

#         # Load the verifier's public key
#         keyset = jwk.JWKSet()
#         keyset.import_keyset(json.dumps(verifier_metadata["jwks"]))
#         # Assuming first key is the intended encryption key
#         public_key = keyset["keys"][0]

#         jwe_token = jwe.JWE(
#             plaintext.encode("utf-8"),
#             protected={
#                 "alg": verifier_metadata["authorization_encrypted_response_alg"],
#                 "enc": "A256GCM",
#             },
#         )
#         jwe_token.add_recipient(jwk.JWK(**public_key))

#         encrypted_response = jwe_token.serialize(compact=True)

#         return {"response": encrypted_response}

#     else:
#         # Plain response with separate fields
#         return {
#             "vp_token": vp_token,
#             "presentation_submission": presentation_submission,
#             "state": state,
#         }

# pid stored credentials
credentials_in_the_wallet = [
    {
        "given_name": "Charlize",
        "family_name": "Theron",
        "birth_date": "1988-12-11",
        "issuing_authority": "EU",
        "issuing_country": "EU",
        "vct": "urn:eu.europa.ec.eudi:pid:1",
        "nationality": ["EU"],
        "birth_place": "EU",
        "issuance_date": "2025-03-24",
        "expiry_date": "2026-03-24",
        "iss": "https://satosa-test-1.sunet.se",
        "iat": 1742832862,
        "exp": 1774368862,
        "cnf": {
            "jwk": {
                "kty": "EC",
                "use": "sig",
                "kid": "V0hZd3hvY0F3LVF2RVJQWHUwYUFIVXRYaDZYc1AzcXpqWjlSWGdxNDFwTQ",
                "crv": "P-256",
                "x": "ZlB4jy20kGUCL1paFcZ93XndwDxlWpZ_tIbt1W6qCkA",
                "y": "2kM0ifDVlSVr4iiNNhHkess6wJoeF1Q01RSNuTiEntU",
            }
        },
    },
    {
        "subject": {
            "date_of_birth": "1988-12-11",
            "family_name": "Theron",
            "forename": "Charlize",
        },
        "social_security_pin": "34567890",
        "period_entitlement": {
            "ending_date": "2026-04-12",
            "starting_date": "2023-03-13",
        },
        "document_id": "67890123456789012345",
        "competent_institution": {
            "institution_country": "FR",
            "institution_id": "CLEISS",
            "institution_name": "Groupe Caisse des D\u00e9p\u00f4ts assisted by the Centre of European and International Liaisons for Social Security",
        },
        "cnf": {
            "jwk": {
                "kid": "UUFKWDlOX1Joc1EyZmFzUXhIUG9YTHpYSmdUS042ODItODg3dWRjNFNRNA",
                "crv": "P-256",
                "kty": "EC",
                "x": "6LwhCEmKevj8qB1FSM179ewKYXAmysE3Eer8JQygqsE",
                "y": "QAPHGWD7WYGjjlBynwbUA0a0UgL_rkHUvlwHT0U8jwo",
            }
        },
        "exp": 1773239644,
        "iss": "https://satosa-dev-1.sunet.se",
        "nbf": 1741703644,
        "vct": "EHICCredential",
    },
]

# TODO:encoded jwt for direct_post.jwt only? can we define the
# type based on form of request only?
qr_code_url = f"verifier-vp://authorize?request={token_in_qr_code}"
# meaning: does this imply
# GET /authorize?
#   response_type=vp_token
#   &client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb
#   &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
#   &presentation_definition=...
#   &transaction_data=...
#   &nonce=n-0S6_WzA2Mj HTTP/1.1
# that it is not direct_post.jwt -- not clear


def parse_qr_code(qr_code_url: str = qr_code_url) -> str:
    # Extract JWT from the scanned URL
    parsed_url = urlparse(qr_code_url)
    jwt_request = parse_qs(parsed_url.query)["request"][0]

    print("JWT from QR code:", jwt_request)
    return jwt_request


def decode_b64url(b64url_str):
    padded = b64url_str + "=" * (-len(b64url_str) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def clean_b64(b64string: str) -> bytes:
    cleaned = b64string.replace("\n", "").replace(" ", "").strip()
    padded = cleaned + "=" * (-len(cleaned) % 4)
    return base64.b64decode(padded)


def get_public_key_from_request(jwt_request) -> EllipticCurvePublicKey:

    # Decode jwt header and payload for inspection (without verifying)
    header_b64, payload, signature = jwt_request.split(".")
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    payload = json.loads(base64.urlsafe_b64decode(payload + "=="))
    print("header:", json.dumps(header, indent=2))
    print("payload", json.dumps(payload, indent=2))
    print(signature)

    cert_der = header.get("x5c")[0]
    cert = x509.der_cert(base64.urlsafe_b64decode(cert_der))
    print(type(cert))
    print(cert.public_key())
    return cert.public_key()


def get_payload(jwt_request) -> Dict[str, Any]:
    _, payload, _ = jwt_request.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload + "=="))
    return payload


def print_cert_info(cert):
    print("subject:", cert.subject.rfc4514_string())
    print("issuer:", cert.issuer.rfc4514_string())
    print("valid urom:", cert.not_valid_before)
    print("valid until:", cert.not_valid_after)
    print("serial number:", cert.serial_number)
    print("signature algorithm:", cert.signature_algorithm_oid._name)


def verify_signature_with_x5c(public_key: EllipticCurvePublicKey) -> Dict[str, Any]:
    jwk = ec.ECKey().load_key(public_key)
    issuer = "vcverifier.sunet.se"
    keyjar = KeyJar()
    keyjar.add_keys(issuer_id=issuer, keys=[jwk])
    jwt = JWT(key_jar=keyjar)

    try:
        payload = jwt.unpack(token_in_qr_code)
        print("verified")
        print(f"payload:{payload}")
        return payload
    except Exception as e:
        print(e.__class__)
        print("verification failed:", str(e))


def are_valid_claims(payload) -> bool:
    """
    TODO: assuming something else should be here
    """
    now = int(time.time())

    if "nbf" in payload and now < payload["nbf"]:
        raise Exception("Token not yet valid")

    if "iat" in payload and now < payload["iat"]:
        raise Exception("Issued At claim is in the future")
    if "response_uri" not in payload:
        raise Exception("No response_uri in the payload")
    return True


def create_wallet_ephemeral_key() -> ec.ECKey:
    """
    Creates key without saving in KeyJar for now
    Can create with min_key() from openid4v
    """
    ephemeral_key = new_ec_key(crv="P-256")
    ephemeral_key.use = "sig"
    return ephemeral_key


def credential_matches_descriptor(credential, descriptor) -> bool:
    # TODO: implement the correct function later
    """
    Function where wallet selects credentials based on the path
    Should be a universal function for PID and other requests
    """
    return True


def get_credentials_for_presentation_submission(
    valid_claims_from_vrtifier_request: Dict[str, Any],
    credentials_in_the_wallet: List[Dict[str, Any]] = credentials_in_the_wallet,
) -> Dict[str, Any]:
    """
    here the wallet selects credentials for
    presentation_submission from presentation_definition
    """
    for credential in credentials_in_the_wallet:
        try:
            credential_matches_descriptor(
                credential, valid_claims_from_vrtifier_request
            )
            # return credentials_for_submission
        except Exception as e:
            raise Exception(f"Something went wrong {e}")
    # TODO:return ehic for now fix later
    # temporarily fix to select EHIC from the fixed list
    credentials_for_submission = [
        cred
        for cred in credentials_in_the_wallet
        if cred.get("vct") == "EHICCredential"
    ][0]
    return credentials_for_submission


def construct_vp_token(credentials_for_submission, ephemeral_key) -> Dict[str, Any]:
    serialized_key = ephemeral_key.serialize()
    vp_token_payload = {
        "iss": "https://wallet.example.org",  # wallet
        "aud": "https://vcverifier.sunet.se",  # TODO:add dynamically
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "exp": int(time.time()) + 7 * 24 * 60 * 60,
        "cnf": {"jwk": serialized_key},
        "verifiableCredential": credentials_for_submission,
    }
    return vp_token_payload


if __name__ == "__main__":
    # get jwt from the verifier request
    jwt_request = parse_qr_code()
    # get public key from the request
    public_key = get_public_key_from_request(jwt_request)
    try:
        # unpack and veryfy the signature, pass for now
        # TODO:remove try, except functionality
        x5c_paylod = verify_signature_with_x5c(public_key)
    except Exception:
        pass
    payload = get_payload(jwt_request)
    # check that all needed parameters are in the claims
    valid_claims_from_vrtifier_request = are_valid_claims(payload)
    # create short term wallet key for signing
    ephemeral_key = create_wallet_ephemeral_key()
    # we get the credentials for submission based on
    # presentation_definition from the  verifier request
    credentials_for_submission = get_credentials_for_presentation_submission(
        valid_claims_from_vrtifier_request, credentials_in_the_wallet
    )
    print(credentials_for_submission)
    vp_details = construct_vp_token(credentials_for_submission, ephemeral_key)
    signer = JWS(vp_details, alg="ES256")
    signed_jwt = signer.sign_compact([ephemeral_key])
    print(signed_jwt)

# TODO: Is direct response type optional? Is it optional=>way to check it
# TODO: For the  direct response flow only
# direct_response={
#     "vp_token":signed_jwt,


#  " presentation_submission":{"id": "123",
#   "definition_id": "VCEuropeanHealthInsuranceCard"(id from the request?),
#   "descriptor_map": [
#     {
#       "id": "VCEHIC",
#       "path": "$"
#     }
#   ]
# }
# "state": "bc1fec73-ee22-405d-9c0e-08ce29db7796" the one in presentation_definition
# }

# TODO: this all should be wrapped in JWT and signed by ephemeral key
# then  verifier callback?response=token
