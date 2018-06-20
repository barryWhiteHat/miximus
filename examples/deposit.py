import sys
sys.path.insert(0, '../snarkWrapper')


from deploy import *

from web3.middleware import geth_poa_middleware
w3.middleware_stack.inject(geth_poa_middleware, layer=0)

if __name__ == "__main__":
    tree_depth = 29


    deployedAddress = "0xB586453a8e44c86E012958E48a0DeCED462BD16e" 

      
    miximus_interface , verifier_interface  = compile(tree_depth)

    miximus = w3.eth.contract(address=deployedAddress, abi=miximus_interface['abi'],ContractFactoryClass=ConciseContract)

    fee = 0 
    depositAddress = Web3.toChecksumAddress(input("enter your deposit addrss, make sure it is unlocked \n"))
    withdrawAddress = Web3.toChecksumAddress(input("enter the address you want to ether to go to \n"))

    nullifier = genNullifier(withdrawAddress)
    sk = "0x" + genSalt(64)

    index = deposit(miximus, nullifier, sk, depositAddress)
    deposit = {"index":index , "nullifier":nullifier , "secretKey":sk}
    f = open("%d.json"%index, "w+") 
    f.write(json.dumps(deposit, ensure_ascii=False))
    f.close()



    print("Ether was deposited, file %s.json was craeted this contains information for miximus to withdraw your funds. Its important that you backup this file. \
          anyone who can see this file will be able to deanonamize you. But they will not be able to steal your funds."% str(index))

    
