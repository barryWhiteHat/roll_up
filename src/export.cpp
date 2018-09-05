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

#include <fstream>
#include <iostream>
#include <cassert>
#include <iomanip>



#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

// ZoKrates
#include <ZoKrates/wraplibsnark.cpp>






//key gen 
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key
#include "libff/algebra/curves/bn128/bn128_pp.hpp" //hold key
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
#include <libff/algebra/curves/edwards/edwards_pp.hpp>







#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/crh_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/digest_selector_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>


// tmp 
//#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

using namespace libsnark;
using namespace libff;


template<typename FieldT>
void constraint_to_json(linear_combination<FieldT> constraints, std::stringstream &ss)
{
    ss << "{";
    uint count = 0;
    for (const linear_term<FieldT>& lt : constraints.terms)
    {
        if (count != 0) {
            ss << ",";
        }
        if (lt.coeff != 0 && lt.coeff != 1) {
            ss << '"' << lt.index << '"' << ":" << "-1";
        }
        else {
            ss << '"' << lt.index << '"' << ":" << lt.coeff;
        }
        count++;
    }
    ss << "}";
}

template <typename FieldT>
void array_to_json(protoboard<FieldT> pb, uint input_variables,  std::string path)
{

    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);

    r1cs_variable_assignment<FieldT> values = pb.full_variable_assignment();
    ss << "\n{\"TestVariables\":[";

    for (size_t i = 0; i < values.size(); ++i)
    {
        ss << values[i].as_bigint();
        if (i <  values.size() - 1) { ss << ",";}
    }

    ss << "]}\n";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename FieldT>
void r1cs_to_json(protoboard<FieldT> pb, uint input_variables, std::string path)
    {
    // output inputs, right now need to compile with debug flag so that the `variable_annotations`
    // exists. Having trouble setting that up so will leave for now.
    r1cs_constraint_system<FieldT> constraints = pb.get_constraint_system();
    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);

    ss << "\n{\"variables\":[";
    
    for (size_t i = 0; i < input_variables + 1; ++i) 
    {   
        ss << '"' << constraints.variable_annotations[i].c_str() << '"';
        if (i < input_variables ) {
            ss << ", ";
        }
    }
    ss << "],\n";
    ss << "\"constraints\":[";
     
    for (size_t c = 0; c < constraints.num_constraints(); ++c)
    {
        ss << "[";// << "\"A\"=";
        constraint_to_json(constraints.constraints[c].a, ss);
        ss << ",";// << "\"B\"=";
        constraint_to_json(constraints.constraints[c].b, ss);
        ss << ",";// << "\"A\"=";;
        constraint_to_json(constraints.constraints[c].c, ss);
        if (c == constraints.num_constraints()-1 ) {
            ss << "]\n";
        } else {
            ss << "],\n";
        }
    }
    ss << "]}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename FieldT>
string proof_to_json(r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof, r1cs_primary_input<FieldT> input, bool isInt) {
    std::cout << "proof.A = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_A.g)<< ");" << endl;
    std::cout << "proof.A_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_A.h)<< ");" << endl;
    std::cout << "proof.B = Pairing.G2Point(" << outputPointG2AffineAsHex(proof.g_B.g)<< ");" << endl;
    std::cout << "proof.B_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_B.h)<<");" << endl;
    std::cout << "proof.C = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_C.g)<< ");" << endl;
    std::cout << "proof.C_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_C.h)<<");" << endl;
    std::cout << "proof.H = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_H)<<");"<< endl;
    std::cout << "proof.K = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_K)<<");"<< endl; 


    std::string path = "../zksnark_element/proof.json";
    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    if(isInt) { 
        ss << "{\n";
        ss << " \"a\" :[" << outputPointG1AffineAsInt(proof.g_A.g) << "],\n";
        ss << " \"a_p\"  :[" << outputPointG1AffineAsInt(proof.g_A.h)<< "],\n";
        ss << " \"b\"  :[" << outputPointG2AffineAsInt(proof.g_B.g)<< "],\n";
        ss << " \"b_p\" :[" << outputPointG1AffineAsInt(proof.g_B.h)<< "],\n";
        ss << " \"c\" :[" << outputPointG1AffineAsInt(proof.g_C.g)<< "],\n";
        ss << " \"c_p\" :[" << outputPointG1AffineAsInt(proof.g_C.h)<< "],\n";
        ss << " \"h\" :[" << outputPointG1AffineAsInt(proof.g_H)<< "],\n";
        ss << " \"k\" :[" << outputPointG1AffineAsInt(proof.g_K)<< "],\n";
        ss << " \"input\" :" << "["; //1 should always be the first variavle passed

        for (size_t i = 0; i < input.size(); ++i)
        {   
            ss << input[i].as_bigint() ; 
            if ( i < input.size() - 1 ) { 
                ss<< ", ";
            }
        }
        ss << "]\n";
        ss << "}";
    }
    else {

        ss << "{\n";
        ss << " \"a\" :[" << outputPointG1AffineAsHex(proof.g_A.g) << "],\n";
        ss << " \"a_p\"  :[" << outputPointG1AffineAsHex(proof.g_A.h)<< "],\n";
        ss << " \"b\"  :[" << outputPointG2AffineAsHex(proof.g_B.g)<< "],\n";
        ss << " \"b_p\" :[" << outputPointG1AffineAsHex(proof.g_B.h)<< "],\n";
        ss << " \"c\" :[" << outputPointG1AffineAsHex(proof.g_C.g)<< "],\n";
        ss << " \"c_p\" :[" << outputPointG1AffineAsHex(proof.g_C.h)<< "],\n";
        ss << " \"h\" :[" << outputPointG1AffineAsHex(proof.g_H)<< "],\n";
        ss << " \"k\" :[" << outputPointG1AffineAsHex(proof.g_K)<< "],\n";
        ss << " \"input\" :" << "["; //1 should always be the first variavle passed

        for (size_t i = 0; i < input.size(); ++i)
        {   
            ss << "\"0x" << HexStringFromLibsnarkBigint(input[i].as_bigint()) << "\""; 
            if ( i < input.size() - 1 ) { 
                ss<< ", ";
            }
        }
        ss << "]\n";
        ss << "}";
    }


    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
    return(ss.str());
}

void vk2json(r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair, std::string path ) {

    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    unsigned icLength = keypair.vk.encoded_IC_query.rest.indices.size() + 1;
    
    ss << "{\n";
    ss << " \"a\" :[" << outputPointG2AffineAsHex(keypair.vk.alphaA_g2) << "],\n";
    ss << " \"b\"  :[" << outputPointG1AffineAsHex(keypair.vk.alphaB_g1) << "],\n";
    ss << " \"c\" :[" << outputPointG2AffineAsHex(keypair.vk.alphaC_g2) << "],\n";
    ss << " \"g\" :[" << outputPointG2AffineAsHex(keypair.vk.gamma_g2)<< "],\n";
    ss << " \"gb1\" :[" << outputPointG1AffineAsHex(keypair.vk.gamma_beta_g1)<< "],\n";
    ss << " \"gb2\" :[" << outputPointG2AffineAsHex(keypair.vk.gamma_beta_g2)<< "],\n";
    ss << " \"z\" :[" << outputPointG2AffineAsHex(keypair.vk.rC_Z_g2)<< "],\n";

    ss <<  "\"IC\" :[[" << outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.first) << "]";
    
    for (size_t i = 1; i < icLength; ++i)
    {   
        auto vkICi = outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.rest.values[i - 1]);
        ss << ",[" <<  vkICi << "]";
    } 
    ss << "]";
    ss << "}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}
template<typename FieldT>
//void dump_key(r1cs_constraint_system<FieldT> cs)
char* dump_key(protoboard<FieldT> pb, std::string path)
{

    r1cs_constraint_system<FieldT> constraints = pb.get_constraint_system();
    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);


    r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = generateKeypair(pb.get_constraint_system());

    //save keys
    vk2json(keypair, "vk.json");
    writeToFile("../zksnark_element/pk.raw", keypair.pk);
    writeToFile("../zksnark_element/vk.raw", keypair.vk);

    pb.primary_input();
    pb.auxiliary_input();

    r1cs_primary_input <FieldT> primary_input = pb.primary_input();
    r1cs_auxiliary_input <FieldT> auxiliary_input = pb.auxiliary_input();
    ss << "primaryinputs" << primary_input;
    ss << "aux input" << auxiliary_input;


    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, primary_input, auxiliary_input);


    auto json = proof_to_json (proof, primary_input);

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();

    auto result = new char[json.size()];
    memcpy(result, json.c_str(), json.size() + 1);



    return result;


}


