import base64
import os
import json

# The URL to encode
url = "https://openidfed-dev-1.sunet.se:7001/"

# Encode the URL in Base64
encoded_url = base64.b64encode(url.encode()).decode()

# The trust anchor public key data to write into the file (as per your provided JSON)
trust_anchor_data = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "QjZ1N2RFTFFST0ZvMWs2NFpiakxCeFV5dGVURjFIWThuUVB3RjRMc0Frdw",
            "n": "hrRAHgzRjUhtHyaaSSruD9Ie89P1FEuhuHviHPSpltHYY7pF5T92tmQUEHCOo0bXmBtvgpCFRxv6SaUHPnex_eUEMPdHsOPMumLtdhciT81ikKpw6Qmfx2EmZ5BbWqeZF0MC5LKiipgN5jQL_WbrkRCVhEfXwMJmnjJNIA3AG94rHOA9b5aXV5EZ7YaiWMJZaOkmRZ1u8O6SoQZW630b4coDAcwsKNoNxUsfqCglsSkX-gs9DAxRfMC9jhO_W1htczxtgjHoQ_wh-fAbI4uJafLj_6FlWIh0C0igewjU8DRQsm2Y0pqWP8ERqKeRx_AQxlzXLd9XIUNXKdTbs0ro-Q",
            "e": "AQAB"
        },
        {
            "kty": "EC",
            "use": "sig",
            "kid": "TjJWS282a3pZSEFhM0IzN05lMmQ4XzdCTldJN2MyVkdzd3FDYktRT2I0Yw",
            "crv": "P-256",
            "x": "WhSm-S0uLFeh-cAr2Nqp0H0tpG9dyOlbP-sLGa8VYM4",
            "y": "06vDA3rcbfq2aN1KGyZCM1zQ-fuGqUdN6ibFTrCawmY"
        }
    ]
}

# Define the directory (you can change this if needed)
directory = "trust_anchors"

# Ensure the directory exists
os.makedirs(directory, exist_ok=True)

# Define file paths based on the Base64-encoded URL
file_path = os.path.join(directory, encoded_url)
lock_file_path = os.path.join(directory, encoded_url + ".lock")

# Write the public key data (trust anchor) into the Base64-named file
with open(file_path, "w") as file:
    json.dump(trust_anchor_data, file, indent=4)

# Write the Base64-encoded URL into the .lock file
with open(lock_file_path, "w") as lock_file:
    lock_file.write(encoded_url)

print(f"Files created with content:\n{file_path}\n{lock_file_path}")
