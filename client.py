import pdb
from fedservice.combo import FederationCombo
from fedservice.utils import make_federation_combo
import json
import os


def discover_issuers(eid):
    """
    First we need to discover all the issuers in the federation.
    We do this by
    """
    trust_chain = get_trust_chains(eid)
    return trust_chain


def wallet_instance_request():
    pass


# main():
# getopt
# param EID
cnf = json.loads(open("client.conf", "r").read())

app.server = make_federation_combo(**cnf["entity"])
pdb.set_trace()
app.federation_entity = app.server["federation_entity"]
app.federation_entity.function.trust_chain_collector.trust_anchors.items()
trust_chain = discover_issuers("EID")
print(f"I found this trust chain: {trust_chain}")



