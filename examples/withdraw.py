'''   
    copyright 2018 to the Miximus Authors

    This file is part of Miximus.

    Miximus is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Miximus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Miximus.  If not, see <https://www.gnu.org/licenses/>.
'''


import sys
sys.path.insert(0, '../snarkWrapper')

from deploy import *


from web3.middleware import geth_poa_middleware
w3.middleware_stack.inject(geth_poa_middleware, layer=0)


if __name__ == "__main__":
    tree_depth = 29

    pk_output = "../zksnark_element/pk_rinkby.raw"
 
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



