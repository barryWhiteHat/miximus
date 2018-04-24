# Miximus
Ethereum Mixer an *EXPERIMENTAL* protoype

## How it works
When someone sends 1 ether to the `deposit` function in miximus.sol they get the right to append single leaf
onto the merkel tree. 

Afterwards someone who has the secret key (sk) and nullifier of the leaf of the merkel tree is allowed to 
withdraw 1 ether. But instead of revealing the information to prove that they control it. They (using a zksnark)
produce a proof that they know this information without revealing it. They also create a proof that their leaf 
is in the merkel tree. 

When they verify this proof they reveal the nullifier, but not the sk. So no one is able to tell which nullifier 
maps to which leaf.

To prevent double spends the smart contract tracks the nullifiers and only allows a single withdrawal per nullifiers. 


## build instructions:



### build libsnark gadget to generate verificaction key and proving key
get dependencies `git submodule update --init --recursive`
`mkdir build` 
`cd build`
`cmake .. && make`
`cd ../zksnark_element && ../build/src/main`

### deploy test contract 
This will deploy the contract and perform a single mixing transaction 
from address `0xffcf8fdee72ac11b5c542428b35eef5769c409f0` to `0x3fdc3192693e28ff6aee95320075e4c26be03308`

`cd snarkWrapper`
`npm install`
`testrpc -d`
`node deploy.js`


## References
This is very similar to [babyZoe](https://github.com/zcash-hackworks/babyzoe/) and its [backend](https://github.com/ebfull/hackishlibsnarkbindings/)
Alessandro Chiesa's [Zero Cash](https://www.youtube.com/watch?v=84Vbj7-i9CI) talk is quite useful to help understand how this works. 
