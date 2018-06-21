import json
import web3

from web3 import Web3, HTTPProvider, TestRPCProvider
from solc import compile_source, compile_standard
from web3.contract import ConciseContract


import pdb
from solc import compile_source, compile_files, link_code
from bitstring import BitArray
import random 

from ctypes import cdll
import ctypes as c

tree_depth = 29
lib = cdll.LoadLibrary('../build/src/libmiximus.so')
#lib = cdll.LoadLibrary('../../test_merkel_tree/build/src/libmiximus.so')

prove = lib.prove
prove.restype = c.c_char_p;
#prove.argtypes = [c.POINTER(c.POINTER(c.c_bool*256))]

prove.argtypes = [((c.c_bool*256)*(tree_depth + 3)), c.c_int, ((c.c_bool*tree_depth)), c.c_int] 
genKeys = lib.genKeys
genKeys.argtypes = [c.c_int, c.c_char_p, c.c_char_p]

helloWorld = lib.helloWorld

helloWorld.restype = c.c_char_p;
helloWorld.argtypes = [c.c_char_p];




w3 = Web3(HTTPProvider("http://localhost:8545"));


def hex2int(elements):
    ints = []
    for el in elements:
        ints.append(int(el, 16))
    return(ints)

def compile(tree_depth):
    miximus = "../contracts/Miximus.sol"
    MerkelTree = "../contracts/MerkelTree.sol"  
    Pairing =  "../contracts/Pairing.sol"
    Verifier = "../contracts/Verifier.sol"

    compiled_sol =  compile_files([Pairing, MerkelTree, Pairing, Verifier, miximus], allow_paths="./contracts")

    miximus_interface = compiled_sol[miximus + ':Miximus']
    verifier_interface = compiled_sol[Verifier + ':Verifier']

    return(miximus_interface, verifier_interface)
   

def deploy(tree_depth, vk_dir):
    miximus_interface , verifier_interface  = compile(tree_depth)
    with open(vk_dir) as json_data:
        vk = json.load(json_data)


    vk  = [hex2int(vk["a"][0]),
           hex2int(vk["a"][1]),
           hex2int(vk["b"]),
           hex2int(vk["c"][0]),
           hex2int(vk["c"][1]),
           hex2int(vk["g"][0]),
           hex2int(vk["g"][1]),
           hex2int(vk["gb1"]),
           hex2int(vk["gb2"][0]),
           hex2int(vk["gb2"][1]),
           hex2int(vk["z"][0]),
           hex2int(vk["z"][1]),
           hex2int(sum(vk["IC"], []))
    ]

     # Instantiate and deploy contract
    miximus = w3.eth.contract(abi=miximus_interface['abi'], bytecode=miximus_interface['bin'])
    verifier = w3.eth.contract(abi=verifier_interface['abi'], bytecode=verifier_interface['bin'])

    # Get transaction hash from deployed contract
    tx_hash = verifier.deploy(args=vk, transaction={'from': w3.eth.accounts[0], 'gas': 4000000})
    # Get tx receipt to get contract address

    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    verifier_address = tx_receipt['contractAddress']


    tx_hash = miximus.deploy(transaction={'from': w3.eth.accounts[0], 'gas': 4000000}, args=[verifier_address])

    # Get tx receipt to get contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    miximus_address = tx_receipt['contractAddress']

    # Contract instance in concise mode
    abi = miximus_interface['abi']
    miximus = w3.eth.contract(address=miximus_address, abi=abi,ContractFactoryClass=ConciseContract)



    return(miximus)

def deposit(miximus, nullifier, sk, depositAddress):
    #FFFF...FFFF is the salt 3fdc....03309 is the address that will recive the funds.

    leaf = miximus.getSha256(nullifier, sk)
    print ("leaf: " , w3.toHex(leaf))
    print ("null: " , nullifier, "sk: " , sk)

    tx_hash = miximus.deposit( leaf, transact={'from': depositAddress, 'gas': 4000000, "value":w3.toWei(1, "ether")})
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    return(int(tx_receipt["logs"][0]["data"], 16))

def withdraw(miximus, pk):
    print( w3.eth.getBalance(miximus.address))
    tx_hash = miximus.withdraw(pk["a"] , pk["a_p"], pk["b"], pk["b_p"] , pk["c"], pk["c_p"] , pk["h"] , pk["k"], pk["input"] , transact={'from': w3.eth.accounts[0], 'gas': 4000000})
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)

    print( w3.eth.getBalance(miximus.address))

def bytesToBinary(hexString):
    out = "" 
    for i, byte in enumerate(hexString):
        out += bin(byte)[2:].rjust(8,"0")
    out = [int(x) for x in out] 
    return((c.c_bool*256)(*out))
    pk = "asdf"

def genhelloWorld(pk_dir):
     pk = helloWorld(c.c_char_p(pk_dir.encode()))
    
def genWitness(miximus, nullifier, sk, address, tree_depth, fee, pk_dir):

    path = []
    address_bits = []
    #tree = miximus.getTree()
    #tree_hex = [w3.toHex(x) for x in tree]
    root = miximus.getRoot()

    path1, address_bits1 = miximus.getMerkelProof(address, call={"gas":500000})
    '''
    for i in range (0 , tree_depth):
        address_bits.append(address%2)
        if ( address %2 == 0) :
            print (w3.toHex(tree[address + 1]))
            path.append(tree[address + 1])
            print (path1[i] == tree[address + 1])
        else:
            print (w3.toHex(tree[address - 1]))
            path.append(tree[address - 1])
            print (path1[i] == tree[address - 1])

        address = int(address/2) 
    '''
    print (address_bits1)
    y = [w3.toHex(x) for x in path1]
    print (y)
    path = [bytesToBinary(x) for x in path1]
       
    address_bits = address_bits1[::-1]

    path = path[::-1]

    path.append(bytesToBinary(w3.toBytes(hexstr=nullifier)))
    path.append(bytesToBinary(w3.toBytes(hexstr=sk)))
    path.append(bytesToBinary(root))

    print ("address bits ",  address_bits)

    path  = ((c.c_bool*256)*(tree_depth + 3))(*path)
    address = 2#int("".join([str(int(x=="True")) for x in address_bits]), 2)
    address_bits = (c.c_bool*tree_depth)(*address_bits)

    print(address)
    print( w3.toHex(root))

    pk = prove(path, address, address_bits, tree_depth, c.c_int(fee),  c.c_char_p(pk_dir.encode()))



    pk = json.loads(pk.decode("utf-8"))
    pk["a"] = hex2int(pk["a"])
    pk["a_p"] = hex2int(pk["a_p"])
    pk["b"] = [hex2int(pk["b"][0]), hex2int(pk["b"][1])]
    pk["b_p"] = hex2int(pk["b_p"])
    pk["c"] = hex2int(pk["c"])
    pk["c_p"] = hex2int(pk["c_p"])
    pk["h"] = hex2int(pk["h"])
    pk["k"] = hex2int(pk["k"])
    pk["input"] = hex2int(pk["input"])   

    return(pk)

def genSalt(i):
    salt = [random.choice("0123456789abcdef0123456789ABCDEF") for x in range(0,i)]
    out = "".join(salt)
    return(out)

def genNullifier(recvAddress):
    salt = genSalt(24)
    return(recvAddress + salt)   
