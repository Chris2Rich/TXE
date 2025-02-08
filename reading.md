# To Read
- https://eprint.iacr.org/2015/308.pdf
- https://bitcoin.org/bitcoin.pdf
- https://www.getmonero.org/resources/research-lab/
- https://downloads.getmonero.org/whitepaper_annotated.pdf
- https://eprint.iacr.org/2007/286.pdf
# Read
- MIT OCW https://ocw.mit.edu/courses/mas-s62-cryptocurrency-engineering-and-design-spring-2018/
- Kaspa Forum https://research.kas.pa/t/a-proposal-for-finality-in-ghostdag/66/2
- https://eprint.iacr.org/2015/625.pdf
- https://cr.yp.to/ecdh/curve25519-20060209.pdf


   ### Layer 1 - Headerchain
   ### Blockchain (easy)
  - Blockchain is really a chain of headers that contain key information about the block, this can be any data I want but must include the hash of the previous header. This is stored on disk.
   - Ability to create blocks on blockchain by pointing to previous block and using a randomly set nonce in such a way that the hash is below the difficulty (Proof of work, this is not proof btw this is always an estimation)
   - Ability to relay blocks once they have been mined so that other nodes can verify
   - When branches are in conflict, the one with the most work will always win regardless of the number of transactions it allows. This is to prevent easy ways to cheat systems based on transactions in easy ways such as forging transaction volume.
   - Difficulty is very arbitrary, as I want fast AND correct transactions, I want to use medium difficulty. Using too low a difficulty means that nodes spend a higher % of compute verifying and building on blocks with bad transactions compared to mining..
  ### Directed Acyclic Graph (hard)
  - Same as blockchain except that instead of cutting off chains that are "outworked" (more work in one chain than other), we store ALL chains as a connected DAG and spread valid nodes throughout network quickly provided that inputs are unique within DAG (trivial to prove as UTXOset can be accessed quickly).
  - Issues come in consensus where an attacker can use a "pruning attack" where a bad block can cause other nodes to mine on top of it and create a hard fork. In simple blockchain this is not an issue as the nodes will reject these blocks and easily find what is correct wasting limited hashrate, especially when difficulty is lower, this is counterintuitive but it is because more "bad" blocks can have valid POW meaning that it is more time consuming to verify transactions than hash.
  - My solution is to simply ignore the fundamental distributed systems problem of synchronisation and to instead, "Only Take What You Need", where a node will recieve a transaction, check if the inputs point to valid utxos in the utxoset and if not, it will ask its neighbours for the blocks that lead up to the transaction. If this block does not know, then it will relay this transaction around the network. To reduce the annoyance of DOS attacks and wasted compute, nodes will by default ignore transactions where the utxos involved are not in the utxoset IF there is not a considerable fee. This means that a new "path" will be created in all the nodes that interact with the block as for an unseen utxo, there is a unique singly linked list of blocks that points ends with it, this means that it will be easier and cheaper to then relay branches of this chain. The transaction's hash will also be added to an "already seen" database so that once a transaction permeates network, it does not cycle. This means that nodes will need significant RAM to handle fast DB indexing for consensus. Where the chain involves a utxo that is already spent on the side of the receiving node, the node will relay the fact that it did not accept the blocks pointing to the invalid block to the sending node. If this is a good node, it will then eliminate these blocks and the recieving node will as well meaning that the double spend is reduced to no spend. This model also allows for "pseudoforking" without introducing double spend issues where if two desynchronised nodes come into contact with each other, they can reconstruct a correct DAG at relatively minimal cost even if transactions are lost.
     
   ### Layer 2 - Transactions
  - Represent all coins as immutable, one use tokens that are not "owned" but instead able to be spent if you have some knowledge that allows you to meet the conditions set by the owner of the previous coins, this allows for very exotic contracts that have real uses in finance and other advanced markets.
  - Coins are also indivisible and infungible in this model.
  - Because coins are infungible and uniquely identifiable this means that for adequate security, a lot is put onto the user who is always ultimately the weakest link, it also allows for chain-analysis to be feasible which is not optimal
  - Use a commitment scheme and zero knowledge proofs to create a transaction model with masked input and output amounts that have the property that consensus can still be reached. Combine with use of ring signatures to mask input addresses to reduce chainanalysis efficiency.
  - Pending transactions are stored in a mempool (this is NOT universal across network for communications reasons). This means that it needs to be possible for a transaction that does not "exist" to be valid (solved by asking "neighbour nodes" to find chain where utxo exists. Made efficient by storing the block a utxo comes from in utxoset. IMPORTANT - this creates metadata of where in the blockchain a transaction occured allowing for dating)
