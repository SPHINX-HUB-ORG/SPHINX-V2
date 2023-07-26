#ifndef COTSHORTKEYS_H___
#define COTSHORTKEYS_H___

#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"
//#include "transpose.h"
#include "COTSK_Prg.h"
//#include "gf2x_util.h"
#define DEBUG_PRINT

#include <cryptoTools/Common/MatrixView.h>

/*
    HELPER METHODS   
*/

const byte BITMASK[8] = { 0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80 };
const uint32_t MOD_MASK = 7; // 0x0...111
inline byte index(const byte *v, const uint32_t & ind) {  return v[ind >> 3] & BITMASK[ind & MOD_MASK]; } 

#endif // COTSHORTKEYS_H___