# Miximus
Decentralized Ethereum Mixer

[![Join the chat at https://gitter.im/barrywhitehat/miximus_eth](https://badges.gitter.im/barrywhitehat/miximus_eth.svg)](https://gitter.im/barrywhitehat/miximus_eth?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)


## How it works
When someone sends 1 ether to the `deposit` function in miximus.sol they append single leaf
to the merkle tree. 

Afterwards someone who has the secret key (sk) and `nullifier` of the leaf of the merkle tree is allowed to 
withdraw 1 ether. But instead of revealing the information to prove that they control it. They (using a zksnark)
produce a proof that they know this information without revealing it. They also create a proof that their leaf 
is in the merkle tree. 

When they verify this proof they reveal the nullifier, but not the sk. So no one is able to tell which nullifier 
maps to which leaf.

To prevent double spends the smart contract tracks the nullifiers and only allows a single withdrawal per nullifiers. 


## build instructions:



### build libsnark gadget and getting the proving key
get dependencies `git submodule update --init --recursive`
`mkdir build` 
`cd build`
`cmake .. && make`

Finally you will need to download the ~400MB proving key from [here](https://github.com/barryWhiteHat/miximus/releases/download/untagged-5e043815d553302be2d2/rinkeby_vk_pk.tar.gz), unzip it and save it in the `./zksnark_element` directory.

### Running the tests
Start your prefered ethereum node, `cd tests` and run `python3 test.py` This will 
1. Generate verification keys, proving keys, This step takes a lot of ram and its likely your OS will kill it if you have a bunch of windows open.
2. deploy the contract
3. Deposit 32 ether in 1 ether chunks.
4. Withdraw the 32 eth so that an observer cannot tell which deposit it was based upon. 

### Examples
The examples are interactive and ask you for the addresses you want to send from and to. The contract is deployed on the Rinkeby test net. These
scripts deposit and withdraw form that contract. 
`cd examples`
deposit `python3 deposit.py` ether this will create a transaction from an account of your chosing to send 1 ether to the smart contract. It will create 
a files of the forum `%d.json` where `%d` is the merkel tree index of your commitment. 

`python3 withdraw.py` will ask you for a file `%d.json` it will call libsnark and generate a proof with proving key `../zksnark_elements/pk_rinkby.raw`
`python3 withdraw.py` takes a long time to run so make sure that your `eth.accounts[0]` is unlocked by the time the transaction gets broadcast. otherwise 
it will drop to pdb debugger.

## Layer 2 transaction abstraction
A major problem in the current system is who pays for the gas for the withdrawal. While the prefect solution to this is to allow the smart contract 
to pay for gas. This is not possible at the moment. There for we provide layer two transaction abstraction where a depositor can define a fee that 
gets paid to whoever pays the gas of a transaction. Future work should formalize a communication channel where people can 
advertise these transactions so that others can pay the gas for them and recive a reward.  


## References
This is very similar to [babyZoe](https://github.com/zcash-hackworks/babyzoe/) and its [backend](https://github.com/ebfull/hackishlibsnarkbindings/)
Alessandro Chiesa's [Zero Cash](https://www.youtube.com/watch?v=84Vbj7-i9CI) talk is quite useful to help understand how this works. 
