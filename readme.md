# TODO
- abstract away ec point type to make operations more secure and encapsulate logic more
- make ec_multiplication more correct by adding handling of identity point
- finish ec_verify, allow for verification of points on a given curve for ecdsa verification to work properly.
- refactor everything to use domain parameters (mostly ec_multiply)
- begin working on headers and mining algorithm !!!!! :D
- add lib/types for all types (keypair and signaturepair), prevents locality of types and allows for structs to be made simpler.