
'''
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
'''

import pdb
import json
from solc import compile_source, compile_files, link_code
from bitstring import BitArray
import random 

from ctypes import cdll
import ctypes as c

import sys
sys.path.insert(0, '../pythonWrapper')
import utils 
from utils import libsnark2python

tree_depth = 2
noTx = 4
lib = cdll.LoadLibrary('../build/src/libroll_up_wrapper.so')


prove = lib.prove
prove.argtypes = [((c.c_bool*256)*(tree_depth)*(noTx)), (c.c_bool*256 * noTx), (c.c_bool*256 * noTx), (c.c_bool*256* noTx), 
                  (((c.c_bool*tree_depth) * noTx)), (c.c_bool*256 * noTx), (c.c_bool*256 * noTx), (c.c_bool*256 * noTx),
                  (c.c_bool*256 * noTx) , (c.c_bool*256* noTx),c.c_int, c.c_int] 

prove.restype = c.c_char_p

genKeys = lib.genKeys
genKeys.argtypes = [c.c_int, c.c_char_p, c.c_char_p]


#verify = lib.verify
#verify.argtypes = [c.c_char_p, c.c_char_p , c.c_char_p , c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p , c.c_char_p, c.c_char_p, c.c_char_p,  c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p, c.c_char_p ]
#verify.restype = c.c_bool


def binary2ctypes(out):
    return((c.c_bool*256)(*out))

def hexToBinary(hexString):
    
    out = [ int(x) for x in bin(int(hexString, 16))[2:].zfill(256)]

    return(out)
  
def genWitness(leaves, public_key_x, public_key_y, address, tree_depth, _rhs_leaf, _new_leaf,r_x, r_y, s):

    path = []
    fee = 0 
    address_bits = []
    pub_key_x = []
    pub_key_y = [] 
    roots = []
    paths = []

    old_leaf = [] 
    new_leaf = []
    r_x_bin_array = []
    r_y_bin_array = []
    s_bin_array = []
    for i in range(noTx): 

        root , merkle_tree = utils.genMerkelTree(tree_depth, leaves[i])
        path , address_bit = utils.getMerkelProof(leaves[i], address[i], tree_depth)

        path = [binary2ctypes(hexToBinary(x)) for x in path] 

        address_bit = address_bit[::-1]
        path = path[::-1]
        paths.append(((c.c_bool*256)*(tree_depth))(*path))


        pub_key_x.append(binary2ctypes(hexToBinary(public_key_x[i])))
        pub_key_y.append(binary2ctypes(hexToBinary(public_key_y[i])))

        roots.append(binary2ctypes(hexToBinary(root)))


        address_bits.append((c.c_bool*tree_depth)(*address_bit))

   
        old_leaf.append(binary2ctypes(hexToBinary(_rhs_leaf[i])))
        new_leaf.append(binary2ctypes(hexToBinary(_new_leaf[i])))

        r_x_bin_array.append(binary2ctypes(hexToBinary(r_x[i])))
        r_y_bin_array.append(binary2ctypes(hexToBinary(r_y[i])))
        s_bin_array.append(binary2ctypes(hexToBinary(hex(s[i]))))



    pub_key_x_array = ((c.c_bool*256)*(noTx))(*pub_key_x)
    pub_key_y_array = ((c.c_bool*256)*(noTx))(*pub_key_y)
    merkle_roots = ((c.c_bool*256)*(noTx))(*roots)
    old_leaf = ((c.c_bool*256)*(noTx))(*old_leaf)
    new_leaf = ((c.c_bool*256)*(noTx))(*new_leaf)
    r_x_bin = ((c.c_bool*256)*(noTx))(*r_x_bin_array)
    r_y_bin = ((c.c_bool*256)*(noTx))(*r_y_bin_array)
    s_bin = ((c.c_bool*256)*(noTx))(*s_bin_array)
    paths = ((c.c_bool*256)*(tree_depth) * noTx)(*paths)
    address_bits = ((c.c_bool)*(tree_depth) * noTx)(*address_bits)

    proof = prove(paths, pub_key_x_array, pub_key_y_array, merkle_roots,  address_bits, old_leaf, new_leaf, r_x_bin, r_y_bin, s_bin, tree_depth, noTx)


    proof = json.loads(proof.decode("utf-8"))
    root , merkle_tree = utils.genMerkelTree(tree_depth, leaves[0])

    return(proof, root)

def genSalt(i):
    salt = [random.choice("0123456789abcdef") for x in range(0,i)]
    out = "".join(salt)
    return(out)

def genNullifier(recvAddress):
    salt = genSalt(24)
    return(recvAddress + salt)   
