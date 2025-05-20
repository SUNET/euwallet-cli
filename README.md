    python3 -m venv venv
    . ./venv/bin/activate
    pip3 install .
    cd src/euwallet_cli
1) ./client.py <client.conf> (e.g client-test.conf)

2) ./client_rework.py <client.conf> (e.g client-test.conf) ehic



Install in development mode
        
        pip install -e '.[dev]' 
 



## Roles and Libraries 

| Category                | Role / Purpose                            | Class / Function                                                     | GitHub Link |
|-------------------------|-------------------------------------------|----------------------------------------------------------------------|-------------|
| Main Handler            | PID-EAA Client Handler                    | `openid4v.client.pid_eaa_consumer.PidEaaHandler`                     | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/pid_eaa_consumer.py) |
| Wallet Core             | Wallet Handler                            | `openid4v.client.Wallet`                                             | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/wallet.py) |
| PID-EAA Service         | Authorization                             | `openid4v.client.pid_eaa.Authorization`                              | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/pid_eaa.py) |
| PID-EAA Service         | Token                                     | `openid4v.client.pid_eaa.AccessToken`                                | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/pid_eaa.py) |
| PID-EAA Service         | Credential Issuance                       | `openid4v.client.pid_eaa.Credential`                                 | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/pid_eaa.py) |
| Wallet Service          | Wallet Instance Attestation               | `openid4v.client.wallet_instance_attestation.WalletInstanceAttestation` | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/wallet_instance_attestation.py) |
| Wallet Service          | Device Integrity                          | `openid4v.client.device_integrity_service.IntegrityService`          | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/device_integrity_service.py) |
| Wallet Service          | Key Attestation                           | `openid4v.client.device_integrity_service.KeyAttestationService`     | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/device_integrity_service.py) |
| Wallet Service          | Registration                              | `openid4v.client.registration.RegistrationService`                   | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/registration.py) |
| Wallet Service          | Challenge                                 | `openid4v.client.challenge.ChallengeService`                         | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/challenge.py) |
| Add-on Extension        | PKCE Support                              | `idpyoidc.client.oauth2.add_on.pkce.add_support`                     | [Source](https://github.com/IdentityPython/idpy-oidc/blob/main/src/idpyoidc/client/oauth2/add_on/pkce.py) |
| Add-on Extension        | DPoP Support                              | `idpyoidc.client.oauth2.add_on.dpop.add_support`                     | [Source](https://github.com/IdentityPython/idpy-oidc/blob/fd283e2573a14ac3e57944118914418719ff070e/src/idpyoidc/client/oauth2/add_on/dpop.py) |
| Add-on Extension        | Pushed Authorization Request (PAR)        | `idpyoidc.client.oauth2.add_on.par.add_support`                      | [Source](https://github.com/IdentityPython/idpy-oidc/blob/fd283e2573a14ac3e57944118914418719ff070e/src/idpyoidc/client/oauth2/add_on/par.py) |
| Auth Method             | JWT Client Attestation                    | `openid4v.client.client_authn.ClientAuthenticationAttestation`       | [Source](https://github.com/SUNET/openid4v/blob/main/src/openid4v/client/client_authn.py) |
| Auth Method             | Request Parameter                         | `idpyoidc.client.client_auth.RequestParam`                           | [Source](https://github.com/IdentityPython/idpy-oidc/blob/fd283e2573a14ac3e57944118914418719ff070e/src/idpyoidc/server/client_authn.py) |
| Auth Method             | DPoP Client Auth                          | `idpyoidc.client.oauth2.add_on.dpop.DPoPClientAuth`                  | [Source](https://github.com/IdentityPython/idpy-oidc/blob/fd283e2573a14ac3e57944118914418719ff070e/src/idpyoidc/client/oauth2/add_on/dpop.py) |

### Not found in libraries 
| Trust Storage           | Trust Anchor Store                        | `idpyoidc.storage.abfile_no_cache.AbstractFileSystemNoCache`         | |





## Persistent Storage 

https://github.com/IdentityPython/idpy-oidc/blob/fd283e2573a14ac3e57944118914418719ff070e/doc/server/contents/persistent_storage.rst
