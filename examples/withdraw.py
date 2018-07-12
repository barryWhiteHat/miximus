import sys
sys.path.insert(0, '../snarkWrapper')

from deploy import *


from web3.middleware import geth_poa_middleware
w3.middleware_stack.inject(geth_poa_middleware, layer=0)


if __name__ == "__main__":
    tree_depth = 29

    pk_output = "../zksnark_element/pk_rinkeby.raw"
 
    deployedAddress = "0xB586453a8e44c86E012958E48a0DeCED462BD16e"
    withdrawIndex = input("Enter the name of the deposit file you would like to use. SHould be something like 0.json\n")

    miximus_interface , verifier_interface  = compile(tree_depth)
    miximus = w3.eth.contract(address=deployedAddress, abi=miximus_interface['abi'],ContractFactoryClass=ConciseContract)


    with open(withdrawIndex) as json_data:
        commitment = json.load(json_data)

    nullifier = commitment["nullifier"]
    sk = commitment["secretKey"]
    i = commitment["index"]
    fee = 0 

    pk = genWitness(miximus, nullifier, sk, i, tree_depth, fee, pk_output)

    try:
        withdraw(miximus, pk)
    except:
        pdb.set_trace()



