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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
const int tree_depth = 2;
char* _sha256Constraints();
char* _sha256Witness();
char* prove(bool path[][tree_depth][256],  bool _pub_key_x[][256], bool _pub_key_y[][256] , bool _root[][256], 
            bool _address_bits[][tree_depth], bool _rhs_leaf[][256], 
            bool _new_leaf[][256], bool _r_x[][256], bool _r_y[][256] , bool _S[][256], int tree_depth, int noTx);
void genKeys(int noTx, char* pkOutput, char* vkOuput );


bool verify( char* vk, char* _g_A_0, char* _g_A_1, char* _g_A_2 ,  char* _g_A_P_0, char* _g_A_P_1, char* _g_A_P_2,
             char* _g_B_1, char* _g_B_0, char* _g_B_3, char* _g_B_2, char* _g_B_5 , char* _g_B_4, char* _g_B_P_0, char* _g_B_P_1, char* _g_B_P_2,
             char* _g_C_0, char* _g_C_1, char* _g_C_2, char* _g_C_P_0, char* _g_C_P_1, char* _g_C_P_2,
             char* _g_H_0, char* _g_H_1, char* _g_H_2, char* _g_K_0, char* _g_K_1, char* _g_K_2, char* _input0 , char* _input1 , char* _input2, char* _input3,
             char* _input4, char* _input5
             ) ;



#ifdef __cplusplus
} // extern "C"
#endif
