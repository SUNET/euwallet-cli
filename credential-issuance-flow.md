```mermaid
sequenceDiagram
  participant User as User
  participant Client as wwWallet
  participant OP as Authorization Server (satosa-frontend OP)
  participant Verifier as Verifier (satosa-backend OP)

  autonumber
  Client ->> Client: Openidfed discovery
  Client ->> OP: Send pushed authorization request (/par)
  note right of OP: Save collect_id, authentic_source, 
  Note right of OP: Save request (authz_details, client_id, state) to session
  OP ->> Client: Redirect to /authorize with request_uri
  Client ->> OP: GET /authorize?request_uri
  OP ->> Client: Redirect to Verifier
  Client ->> Verifier: GET 
  Verifier ->> Client: presentation-description with x5c
  Client ->> User: Which PID do you want to login with?
  User ->> Client: Select PID
  Client ->> Verifier: Present PID
  note right of Verifier: Verify a+b+c,<br> pick out first_name, last_name and birth-date
  Note right of OP: Store authenticated=true, issue grant & code
  Verifier ->> Client: Redirect to satosa-frontend with authorization code
  Client ->> OP: Present authorization code
  OP ->> Client: Send EHIC credential
  Client ->> User: Display EHIC
```

##2
```
send: b'POST /par HTTP/1.1\r\nHost: satosa-dev-1.sunet.se\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nOAuth-Client-Attestation: eyJ0eXAiOiJ3YWxsZXQtYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYiLCJraWQiOiJORzQxY0hCQ1JIUXlPVkpCTUhsZlZGTjVXbWRIVWxCa05tWkZWVVJYTkcxTGVVMUVXa2h2UVdOcmN3In0.eyJzdWIiOiAiYmpOVFRGSnJlVWx6WmpndFFpMWtaRkZzVVZSd1dtRjZUMXBZWDFOUVoyaGpkM1F5WlUxeVJsVmtUUSIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgInVzZSI6ICJzaWciLCAia2lkIjogImJqTlRURkpyZVVselpqZ3RRaTFrWkZGc1VWUndXbUY2VDFwWVgxTlFaMmhqZDNReVpVMXlSbFZrVFEiLCAiY3J2IjogIlAtMjU2IiwgIngiOiAiTDRMTFBwelFfNW5FRGUwQ05NU3g3NzZUTENNTkVoU2F2M1ZjS19IV01lSSIsICJ5IjogIkxOYWRNXzhlY3h6bFlKV0FlaHNGT09wZHZFS0IzSklPQm9mX1BnQXQ1S2cifX0sICJ2cF9mb3JtYXRzX3N1cHBvcnRlZCI6IHsiand0X3ZjX2pzb24iOiB7ImFsZ192YWx1ZXNfc3VwcG9ydGVkIjogWyJFUzI1NksiLCAiRVMzODQiXX0sICJqd3RfdnBfanNvbiI6IHsiYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOiBbIkVTMjU2SyIsICJFZERTQSJdfX0sICJhdXRob3JpemF0aW9uX2VuZHBvaW50IjogImV1ZGl3OiIsICJyZXNwb25zZV90eXBlc19zdXBwb3J0ZWQiOiBbInZwX3Rva2VuIl0sICJyZXNwb25zZV9tb2Rlc19zdXBwb3J0ZWQiOiBbImZvcm1fcG9zdC5qd3QiXSwgInJlcXVlc3Rfb2JqZWN0X3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOiBbIkVTMjU2Il0sICJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmlfc3VwcG9ydGVkIjogZmFsc2UsICJhYWwiOiAiaHR0cHM6Ly90cnVzdC1saXN0LmV1L2FhbC9oaWdoIiwgImlzcyI6ICJodHRwczovL29wZW5pZGZlZC1kZXYtMS5zdW5ldC5zZTo1MDAxIiwgImlhdCI6IDE3NDU5MDYyNDEsICJleHAiOiAxNzQ1OTkyNjQxLCAianRpIjogIjNhOGZmODdlOTY1NDQ1OTNhZGI1YjA4ZWNlMThlYzc5In0.nOqN-8ns7LJ0worVEgc3iKf4le49OkvjsMp99TfwgCIykDpNzw1NJsiZwlG8FMQjsOvbOOeb53VlNj0wb44cUw\r\nOAuth-Client-Attestation-PoP: eyJhbGciOiJFUzI1NiIsImtpZCI6ImJqTlRURkpyZVVselpqZ3RRaTFrWkZGc1VWUndXbUY2VDFwWVgxTlFaMmhqZDNReVpVMXlSbFZrVFEifQ.eyJhdWQiOiAiaHR0cHM6Ly9zYXRvc2EtZGV2LTEuc3VuZXQuc2UiLCAiaXNzIjogImJqTlRURkpyZVVselpqZ3RRaTFrWkZGc1VWUndXbUY2VDFwWVgxTlFaMmhqZDNReVpVMXlSbFZrVFEiLCAiaWF0IjogMTc0NTkwNjI1MiwgImV4cCI6IDE3NDU5MDY1NTIsICJqdGkiOiAiNzEzNWRkMWM3YTBmNGI0MGE0NmY0ZGQyNDBkZTU1MDkifQ.wfbLa38qEY_ljhjzBDq-TryQGgxktqDGYcMkcofhbJUfP_-lZ3GWuN31hjPpL77nKN7qhFTngjAaefAzpcW6XQ\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 527\r\n\r\n'
send: b'authorization_details=%5B%27type%3Dopenid_credential%26format%3Dvc%252Bsd-jwt%26vct%3DEHICCredential%27%5D&response_type=code&client_id=bjNTTFJreUlzZjgtQi1kZFFsUVRwWmF6T1pYX1NQZ2hjd3QyZU1yRlVkTQ&redirect_uri=https%3A%2F%2F127.0.0.1%3A5005%2Fauthz_cb%2Fl7DsnceUVxkrv894Pqv-IdaqL3NfUU-eHnD2NaVqfKc&return_uri=mifr_was_here&issuer_state=collect_id%3Dcollect_id_ehic_122%26authentic_source%3DEHIC%253A00001&state=WjFEhPJeSndxHgukyG0aVgAMdNII0ltM&code_challenge=mmT_nS-_PTI3m94Au1JHrPHKrhbuaq-HdeDTNV4-9qQ&code_challenge_method=S256'
```
##3
```
reply: 'HTTP/1.1 200 OK\r\n'
header: Server: gunicorn
header: Date: Tue, 29 Apr 2025 05:57:33 GMT
header: Connection: close
header: Transfer-Encoding: chunked
header: Content-Type: application/json
header: Set-Cookie: SATOSA_STATE="_Td6WFoAAATm1rRGAgAhARYAAAB0L-Wj4AC_ALddADCZAmVn5x9_tMJLAXGVr_fyskEVG9JhwzO4G_gkZB4ERamWd_9I9SPSY4x3iWNG09PX_rE-zEMK2yFW2_o44LPxFm2FFm59wecPs6jt9DnkfCywBmaHPVaJ21gkBtyAmU7Frsz8oA4I7mvR2F62HheE0LYUz5PJAxTI3Hta4v-njcVN2gJWpPFlMtRCufx8GzcrkuGmKWj6n9Zkq_qMkwXEVpK_D6_cpP4vvJjHwOZ_ir8yR8XiAAAAHl6G-D0IQzYAAdMBwAEAAN0XEB2xxGf7AgAAAAAEWVo="; Path=/; SameSite=None; Secure
```
##4
```
send: b'GET /authorization?request_uri=urn%3Auuid%3A07994a8c-6cb5-4657-8a78-3c5eb7966cdd&response_type=code&client_id=bjNTTFJreUlzZjgtQi1kZFFsUVRwWmF6T1pYX1NQZ2hjd3QyZU1yRlVkTQ HTTP/1.1\r\nHost: satosa-dev-1.sunet.se\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n'
```
##5
```
reply: 'HTTP/1.1 302 Found\r\n'
header: Server: gunicorn
header: Date: Tue, 29 Apr 2025 05:57:38 GMT
header: Connection: close
header: Transfer-Encoding: chunked
header: Content-Type: text/html
header: Location: NOT_FOUND_IN_STATE://?client_id=https%3A%2F%2Fsatosa-dev-1.sunet.se%2FOpenID4VP&request_uri=https%3A%2F%2Fsatosa-dev-1.sunet.se%2FOpenID4VP%2Frequest-uri%3Fid%3Def6a7911-f630-4144-8e09-7ca24731acc5
header: Set-Cookie: SATOSA_STATE="_Td6WFoAAATm1rRGAgAhARYAAAB0L-Wj4AG_AYtdACSeRgQzEre5W9WUVteTsRzO0A7ZkLGMy5OJFd6qI556dnbhcG0EHeUbPBZcUOVTQZZaEVpirho4Tr0AgAy5Re8W-lgZCn37zOakM3WpdNzh2hcFZrkP1iI0GzGftn_eh-T0ZmCgROIR9F7fnbRjpSuy5OSuHly6X_cQMEwYNEKfrMiLGP_dWH1JUChRIv6S4dfURBu8wbi2LsdaVNz_q_R3t3QFsXFITv4BD5mxN4VQt0pEEHMEOVCX19HwrfEYxGhSjRWO0W-TphiRlwLxlMyioGGqS5tq3Mr58TkwpZ2Kus4ItVYaiX49k_3BtG3YKUBheISkX_4A6KkYLNDP3F2M1sEOfOTHVyL2sywaShjBklcrgV4-cfP-OoQBI68w-ZdDGxWBkjCZCCcgcv7jvSocSv5V3A7ugyMdJZ8gB79ruigVp95O-PlvpW5RJ-dF9XsYubEx16duCJpLJ9cKSnXweBmGvAPJsjDHl4TrHWIKcyFv9KYbKeJSPPxJoLUp0BgBY6BwNlkJ2bg0AAASK7CvMypEkwABpwPAAwAABN_n9LHEZ_sCAAAAAARZWg=="; Path=/; SameSite=None; Secure
```