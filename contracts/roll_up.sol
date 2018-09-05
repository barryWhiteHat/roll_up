/*    
    copyright 2018 to the roll_up Authors

    This file is part of roll_up.

    roll_up is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    roll_up is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with roll_up.  If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity ^0.4.19;

import "../contracts/Verifier.sol";

contract roll_up{
    bytes32 root;
    mapping (bytes32 => bool) nullifiers;
    event Withdraw (address); 
    Verifier public zksnark_verify;
    function roll_up (address _zksnark_verify, bytes32 _root) {
        zksnark_verify = Verifier(_zksnark_verify);
        root = _root;
    }

    function isTrue (
            uint[2] a,
            uint[2] a_p,
            uint[2][2] b,
            uint[2] b_p,
            uint[2] c,
            uint[2] c_p,
            uint[2] h,
            uint[2] k,
            uint[] input
        ) returns (bool) {

        bytes32 _root = padZero(reverse(bytes32(input[0]))); //)merge253bitWords(input[0], input[1]);
        require(_root == padZero(root));
        require(zksnark_verify.verifyTx(a,a_p,b,b_p,c,c_p,h,k,input));      
        root = padZero(reverse(bytes32(input[2])));
        return(true);
    }

    function getRoot() constant returns(bytes32) {
        return(root);
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
