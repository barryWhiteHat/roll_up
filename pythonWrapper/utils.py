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
import hashlib 

import sys
sys.path.insert(0, "../depends/baby_jubjub_ecc/tests")

import ed25519 as ed

def hex2int(elements):
    ints = []
    for el in elements:
        ints.append(int(el, 16))
    return(ints)

def normalize_proof(proof):
    proof["a"] = hex2int(proof["a"])
    proof["a_p"] = hex2int(proof["a_p"])
    proof["b"] = [hex2int(proof["b"][0]), hex2int(proof["b"][1])]
    proof["b_p"] = hex2int(proof["b_p"])
    proof["c"] = hex2int(proof["c"])
    proof["c_p"] = hex2int(proof["c_p"])
    proof["h"] = hex2int(proof["h"])
    proof["k"] = hex2int(proof["k"])
    proof["input"] = hex2int(proof["input"]) 
    
    return proof

def getSignature(m,sk,pk):

   R,S = ed.signature(m,sk,pk)
   return(R,S) 


def createLeaf(public_key , message):
    pk = ed.encodepoint(public_key)
    leaf = hashPadded(pk, message)

    return(leaf[2:])

def libsnark2python (inputs):   
    #flip the inputs

    bin_inputs = []
    for x in inputs:
        binary = bin(x)[2:][::-1]

        if len(binary) > 100:
            binary = binary.ljust(253, "0")          
        bin_inputs.append(binary)
    raw = "".join(bin_inputs)

    raw += "0" * (256 * 5 - len(raw)) 

    output = []
    i = 0
    while i < len(raw):
        hexnum = hex(int(raw[i:i+256], 2))
        #pad leading zeros
        padding = 66 - len(hexnum)
        hexnum = hexnum[:2] + "0"*padding + hexnum[2:]

        output.append(hexnum)
        i += 256
    return(output)

def hashPadded(left, right):
    x1 = int(left , 16).to_bytes(32, "big")
    x2 = int(right , 16).to_bytes(32, "big")    
    data = x1 + x2 
    answer = hashlib.sha256(data).hexdigest()
    return("0x" + answer)

def sha256(data):
    data = str(data).encode()
    return("0x" + hashlib.sha256(data).hexdigest())

def getUniqueLeaf(depth):
    inputHash = "0x0000000000000000000000000000000000000000000000000000000000000000"
    for i in range(0,depth):
        inputHash = hashPadded(inputHash, inputHash)
    return(inputHash)

def genMerkelTree(tree_depth, leaves):

    tree_layers = [leaves ,[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]] 

    for i in range(0, tree_depth):
        if len(tree_layers[i]) % 2 != 0:
            tree_layers[i].append(getUniqueLeaf(i))
        for j in range(0, len(tree_layers[i]), 2):
            tree_layers[i+1].append(hashPadded(tree_layers[i][j], tree_layers[i][j+1]))

    return(tree_layers[tree_depth][0] , tree_layers)

def getMerkelRoot(tree_depth, leaves):
    genMerkelTree(tree_depth, leaves)  

def getMerkelProof(leaves, index, tree_depth):
    address_bits = []
    merkelProof = []
    mr , tree = genMerkelTree(tree_depth, leaves)
    for i in range(0 , tree_depth):
        address_bits.append(index%2)
        if (index%2 == 0): 
            merkelProof.append(tree[i][index + 1])
        else:
            merkelProof.append(tree[i][index - 1])
        index = int(index/2);
    return(merkelProof, address_bits); 

def testHashPadded():
    left = "0x0000000000000000000000000000000000000000000000000000000000000000"
    right = "0x0000000000000000000000000000000000000000000000000000000000000000"
    res = hashPadded(left , right)
    assert (res == "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")

def testGenMerkelTree():
    mr1, tree = genMerkelTree(1, ["0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000"]) 
    mr2, tree = genMerkelTree(2, ["0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000", 
                      "0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000"])
    mr3, tree = genMerkelTree(29, ["0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000"])
    assert(mr1 == "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b") 
    assert(mr2 == "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71")

def testlibsnarkTopython():
    inputs = [12981351829201453377820191526040524295325907810881751591725375521336092323040, 
              2225095499654173609649711272123535458680077283826030252600915820706026312895, 
              10509931637877506470161905650895697133838017786875388895008260393592381807236, 
              11784807906137262651861317232543524609532737193375988426511007536308407308209, 17]

    inputs = [9782619478414927069440250629401329418138703122237912437975467993246167708418,
              2077680306600520305813581592038078188768881965413185699798221798985779874888,
              4414150718664423886727710960459764220828063162079089958392546463165678021703,
              7513790795222206681892855620762680219484336729153939269867138100414707910106,
              902]

    output = libsnark2python(inputs)
    print(output)
    assert(output[0] == "0x40cde80490e78bc7d1035cbc78d3e6be3e41b2fdfad473782e02e226cc2305a8")
    assert(output[1] == "0x918e88a16d0624cd5ca4695bd84e23e4a6c8a202ce85560d3c66d4ed39bf4938")
    assert(output[2] == "0x8dd3ea28fe8d04f3e15b787fec7e805e152fe7d3302d0122c8522bee1290e4b7")
    assert(output[3] == "0x47a6bbcf8fa3667431e895f08cbd8ec2869a31698d9cf91e5bfd94cbca72161c")

def testgetMissingLeaf():
    assert (getMissingLeaf(0) == "0x0000000000000000000000000000000000000000000000000000000000000000")
    assert (getMissingLeaf(1) == "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")
    assert (getMissingLeaf(2) == "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71") 
    assert (getMissingLeaf(3) == "0xc78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c")
    assert (getMissingLeaf(4) == "0x536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c")

def testgetMerkelProof():
    proof1, address1 =  getMerkelProof(["0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000",
                      "0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000"] , 0 , 2)
    assert ( proof1[0] == "0x0000000000000000000000000000000000000000000000000000000000000000")
    assert ( proof1[1] == "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")
    assert ( address1[0] == 0)
    assert ( address1[1] == 0)
 
