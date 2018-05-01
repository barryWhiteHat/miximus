var Web3 = require('web3');
var Solidity = require('solc')
var fs = require("fs");
var BigNumber = require('bignumber.js');
const leftPad = require('left-pad')


// get verifcation key, proving key 
var proof = require('../zksnark_element/proof.json');
var vk = require('../zksnark_element/vk.json');
// hack until solidyt allows passing two dimentional arrays. 

var tmp = []
for (var i = 0; i < vk.IC.length; i++) {

    tmp = [].concat(tmp, vk.IC[i])
}
vk.IC = tmp;


var input = {
	'Miximus.sol': fs.readFileSync("./contracts/Miximus.sol", "utf8"),
	'Verifier.sol': fs.readFileSync("./contracts/Verifier.sol", "utf8"), 
        'MerkelTree.sol': fs.readFileSync("./contracts/MerkelTree.sol", "utf8"),
        'Pairing.sol': fs.readFileSync("./contracts/Pairing.sol", "utf8")
}

var compiled = Solidity.compile({sources: input}, 1)
console.log(compiled);

var snark_bytecode = compiled.contracts["Verifier.sol:Verifier"].bytecode;
var snark_abi = compiled.contracts["Verifier.sol:Verifier"].interface;

var miximus_bytecode = compiled.contracts["Miximus.sol:Miximus"].bytecode;
var miximus_abi = compiled.contracts["Miximus.sol:Miximus"].interface;

var snark_abi = JSON.parse(snark_abi);
var miximus_abi = JSON.parse(miximus_abi);

if (typeof web3 !== 'undefined') {
  web3 = new Web3(web3.currentProvider);
} else {
  // set the provider you want from Web3.providers
  web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
}

var snark = web3.eth.contract(snark_abi);
miximus = web3.eth.contract(miximus_abi);
snark.new(
     vk.a[0], 
     vk.a[1],  
     vk.b, 
     vk.c[0], 
     vk.c[1],
     vk.g[0], 
     vk.g[1], 
     vk.gb1, 
     vk.gb2[0], 
     vk.gb2[1],
     vk.z[0], 
     vk.z[1],
     vk.IC,  
     {
     from: web3.eth.accounts[1], 
     data: snark_bytecode, 
     gas: '5000000'
   }, function (e, contract){
    console.log("deploy verifyer", e);
    if (typeof contract.address !== 'undefined') {
        snark_deployed = snark.at(contract.address);
        console.log(snark_deployed.address);
            console.log("len:: ", snark_deployed.getICLen.call());
            miximus.new(snark_deployed.address, {
                        from:web3.eth.accounts[1],
                        data: miximus_bytecode,
                        gas: '6000000'
                       }, function(e, contract) {
                          console.log("deploy mix ", e);
                           if (typeof contract.address !== 'undefined') {
                               console.log("deployed err: ", e);
                               miximus_deployed = contract;
                               console.log(miximus_deployed.address);
                               //FFFF...FFFF is the salt 3fdc....03309 is the address that will recive the funds.
                               nullifier = "0x3fdc3192693e28ff6aee95320075e4c26be03309FFFFFFFFFFFFFFFFFFFFFFFA";
                               sk = "0xc9b94d9a757f6a57e38809be7dca7599fb0d1bb5ee6b2e7c685092dd8b5e71db";
                               miximus_deployed.getSha256(nullifier, sk, function (e, leaf) { 
                                   console.log("leaf: ", leaf, "\n", nullifier, sk);
                                   miximus_deployed.deposit(leaf, {from:web3.eth.accounts[1], gas: 6000000, value:web3.toWei(1,"ether")}, function(err, success) {
                                       console.log(miximus_deployed.getTree());
                                       console.log("Balance :", web3.eth.getBalance(miximus_deployed.address));
                                       console.log("inputs size: " , proof.input.length, vk.IC.length);
                                       miximus_deployed.withdraw(
                                           proof.a,
                                           proof.a_p,
                                           proof.b,
                                           proof.b_p,
                                           proof.c,
                                           proof.c_p,
                                           proof.h,
                                           proof.k,
                                           proof.input,
                                           {from:web3.eth.accounts[1], gas:6000000}, function ( err, res) {
                                               console.log("verifyed: " , res, err);
                                               //you will notice here that 0x3fdc...03308!= 3fdc....03309 from above
                                               // this is a small bug in libsnark that i have raised with them. 
                                               console.log(web3.eth.getBalance("0x3fdc3192693e28ff6aee95320075e4c26be03309"));
                                               miximus_deployed.getTree( function (err, tree) { 
                                                   //TODO: fix dropping of leading zeros, tree17 should print 256 0's
                                                   // same issues in other variables causes a problem in main.cpp
                                                   leaf = new BigNumber(tree[16], 16).toString(2).split("").join(" ,");
                                                   tree17 = new BigNumber(tree[17], 16).toString(2).split("").join(" ,");
                                                   tree9 = new BigNumber(tree[9], 16).toString(2).split("").join(" ,");
                                                   tree5 = new BigNumber(tree[5], 16).toString(2).split("").join(" ,");
                                                   tree3 = new BigNumber(tree[3], 16).toString(2).split("").join(" ,");
                                                   rt = new BigNumber(tree[1], 16).toString(2).split("").join(" ,");
                                                   cm = new BigNumber(nullifier, 16).toString(2).split("").join(" ,");
                                                   secret = new BigNumber(sk, 16).toString(2).split("").join(" ,");
                                                   console.log( 
                                                      "libff::bit_vector tree17 = {", tree17, "};\n" , 
                                                      "libff::bit_vector tree16 = {", leaf, "};\n" , 
                                                      "libff::bit_vector tree9 = {", tree9, "};\n",  
                                                      "libff::bit_vector tree5 = {", tree5, "};\n",   
                                                      "libff::bit_vector tree3 = {", tree3, "};\n", 
                                                      "libff::bit_vector root = {", rt, "};\n", 
                                                      "libff::bit_vector nullifier = {", cm , "};\n",
                                                      "libff::bit_vector secret = {", secret , "};\n");
                                               });
                                          });
                                    });
                              });
                           }   
                       });
    }


 })



