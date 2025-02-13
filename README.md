    python3 -m venv venv
    . ./venv/bin/activate
    pip3 install .
    cd src
    python3 client.py





```
curl -k "https://127.0.0.1:5005/wallet_provider?entity_id=https://openidfed-dev-1.sunet.se:5001"
```

```
curl -k "https://127.0.0.1:5005/wallet_instance_request
```

```
curl -k "https://127.0.0.1:5005/qr_code?collect_id=aads&authentic_source=sdas&document_type=EHIC"
```

```
curl -k "https://127.0.0.1:5005/authz"
```
On the next step need to call the redirect 

```
curl -k "https://127.0.0.1:5005/token"
```

```
curl -k "https://127.0.0.1:5005/credential"
```
