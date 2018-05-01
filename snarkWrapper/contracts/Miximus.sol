pragma solidity ^0.4.19;

import "MerkelTree.sol";
import "Verifier.sol";

contract Miximus is MerkelTree {
    mapping (bytes32 => bool) roots;
    mapping (bytes32 => bool) nullifiers;
    event Withdraw (address); 
    Verifier public zksnark_verify;
    function Miximus (address _zksnark_verify) {
        zksnark_verify = Verifier(_zksnark_verify);
    }

    function deposit (bytes32 leaf) payable  {
        require(msg.value == 1 ether);
        insert(leaf);
        roots[padZero(getTree()[1])] = true;
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
            uint[] input
        ) returns (address) {
        address recipient  = nullifierToAddress(reverse(bytes32(input[2])));      
        require(roots[reverse(bytes32(input[0]))]);

        require(!nullifiers[reverse(bytes32(input[2]))]);
        require(zksnark_verify.verifyTx(a,a_p,b,b_p,c,c_p,h,k,input));
        recipient.transfer(1 ether);
        nullifiers[padZero(reverse(bytes32(input[2])))] = true;
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


    // hack to side step a libshark only allows 253 bit chunks in its output
    // to overcome this we only validate the first 252 bits of the merkel root
    // and the nullifier. We set the last byte to zero.
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
