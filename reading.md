# To Read
- https://eprint.iacr.org/2015/308.pdf
- https://bitcoin.org/bitcoin.pdf
- https://www.getmonero.org/resources/research-lab/
- https://downloads.getmonero.org/whitepaper_annotated.pdf
# Read
- MIT OCW https://ocw.mit.edu/courses/mas-s62-cryptocurrency-engineering-and-design-spring-2018/
  ## Notes
     ### Layer 1 - Headerchain
     - Blockchain is really a chain of headers that contain key information about the block, this can be any data I want but must include the hash of the previous header. This is stored on disk.
     - Ability to create blocks on blockchain by pointing to previous block and using a randomly set nonce in such a way that the hash is below the difficulty (Proof of work, this is not proof btw this is always an estimation)
     - Ability to relay blocks once they have been mined so that other nodes can verify
     - When branches are in conflict, the one with the most work will always win regardless of the number of transactions it allows. This is to prevent easy ways to cheat systems based on transactions in easy ways such as forging transaction volume.
     - Difficulty is very arbitrary, as I want fast transactions, I want to use very low difficulty (on order of ~30s)
       
     ### Layer 2 - Transactions
    ### UXTO Model
    - Represent all coins as immutable, one use tokens that are not "owned" but instead able to be spent if you have some knowledge that allows you to meet the conditions set by the owner of the previous coins, this allows for very exotic contracts that have real uses in finance and other advanced markets.
    - Coins are also indivisible and infungible in this model.
    - Because coins are infungible and uniquely identifiable this means that for adequate security, a lot is put onto the user who is always ultimately the weakest link, it also allows for chain-analysis to be feasible which is not optimal
