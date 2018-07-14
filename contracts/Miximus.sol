pragma solidity ^0.4.19;

import "../contracts/ERC20.sol";
import "../contracts/MerkleTree.sol";
import "../contracts/Verifier.sol";

contract Miximus {

    struct Mixer {
        Mtree MT;
        mapping (bytes32 => bool) roots;
        mapping (bytes32 => bool) nullifiers;
    }

    // address(0x0) means mixing Ether
    mapping(address => Mixer) mixers;

    event Withdraw (address); 
    Verifier public zksnark_verify;
    function Miximus (address _zksnark_verify) {
        zksnark_verify = Verifier(_zksnark_verify);
    }

    function deposit (address _tokenAddress, bytes32 leaf) payable  {
        if(address(0x0) == _tokenAddress) {
            require(msg.value == 1 ether);
        }
        else {
            require(ERC20(_tokenAddress).transferFrom(msg.sender, address(this), 1));
        }
        insert(mixers[_tokenAddress].MT, leaf);
        mixers[_tokenAddress].roots[padZero(getRoot(mixers[_tokenAddress].MT))] = true;
    }

    function withdraw (
            uint[2] a,
            uint[2] a_p,
            uint[2][2] b,
            uint[2] b_p,
            uint[2] c,
            uint[2] c_p,
            uint[2] h,
            uint[2] k,
            uint[] input,
            address _tokenAddress
        ) returns (address) {
        address recipient  = nullifierToAddress(reverse(bytes32(input[2])));      
        bytes32 root = padZero(reverse(bytes32(input[0]))); //)merge253bitWords(input[0], input[1]);

        bytes32 nullifier = padZero(reverse(bytes32(input[2]))); //)merge253bitWords(input[2], input[3]);
        
        require(mixers[_tokenAddress].roots[root]);
        require(!mixers[_tokenAddress].nullifiers[nullifier]);

        require(zksnark_verify.verifyTx(a,a_p,b,b_p,c,c_p,h,k,input));
        mixers[_tokenAddress].nullifiers[nullifier] = true;
        

        if(_tokenAddress == address(0x0)){
            uint fee = input[4];
            require(fee < 1 ether); 
            if (fee != 0 ) { 
                msg.sender.transfer(fee);
            }
            recipient.transfer(1 ether - fee);
        }
        else {
            // TODO: fee?
            require(ERC20(_tokenAddress).transfer(msg.sender, 1));
        }      

        Withdraw(recipient); 
        return(recipient);
    }

    function nullifierToAddress(bytes32 source) returns(address) {
        bytes20[2] memory y = [bytes20(0), 0];
        assembly {
            mstore(y, source)
            mstore(add(y, 20), source)
        }
        //trace(source, y[0], y[1]);
        return(address(y[0]));
    }

    // libshark only allows 253 bit chunks in its output
    // to overcome this we merge the first 253 bits (left) with the remaining 3 bits
    // in the next variable (right)

    function merge253bitWords(uint left, uint right) returns(bytes32) {
        right = pad3bit(right);
        uint left_msb = uint(padZero(reverse(bytes32(left))));
        uint left_lsb = uint(getZero(reverse(bytes32(left))));
        right = right + left_lsb;
        uint res = left_msb + right; 
        return(bytes32(res));
    }


    // ensure that the 3 bits on the left is actually 3 bits.
    function pad3bit(uint input) constant returns(uint) {
        if (input == 0) 
            return 0;
        if (input == 1)
            return 4;
        if (input == 2)
            return 4;
        if (input == 3)
            return 6;
        return(input);
    }

    function getZero(bytes32 x) returns(bytes32) {
                 //0x1111111111111111111111113fdc3192693e28ff6aee95320075e4c26be03308
        return(x & 0x000000000000000000000000000000000000000000000000000000000000000F);
    }

    function padZero(bytes32 x) returns(bytes32) {
                 //0x1111111111111111111111113fdc3192693e28ff6aee95320075e4c26be03308
        return(x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0);
    }

    function reverseByte(uint a) public pure returns (uint) {
        uint c = 0xf070b030d0509010e060a020c0408000;

        return (( c >> ((a & 0xF)*8)) & 0xF0)   +  
               (( c >> (((a >> 4)&0xF)*8) + 4) & 0xF);
    }
    //flip endinaness
    function reverse(bytes32 a) public pure returns(bytes32) {
        uint r;
        uint i;
        uint b;
        for (i=0; i<32; i++) {
            b = (uint(a) >> ((31-i)*8)) & 0xff;
            b = reverseByte(b);
            r += b << (i*8);
        }
        return bytes32(r);
    }

}
