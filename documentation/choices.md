Using ed25519 from Crypto++ for a secure implementation of ecdsa (fast and very secure)
use an improvement of RingCT (CRCT (constant ring confidential transactions)), uses combination of ZKP for amount masking as well as user generated ring signatures to mask addresses. because ringct doesnt use constant size ring signatures, it results in monero blockchain being 8x bigger than it has to be
use POW for consensus
uses DAG to represent blockchain, simply allows for multiple pointers
use fast database to make DAG fast