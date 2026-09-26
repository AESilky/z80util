/**
 * @brief Z80 Disassembler Library
 * @file z80disasm.h
 *
 *
 * Copyright 2026 AESilky
 * SPDX-License-Identifier: MIT License
 */

#include "z80disasm.h"
#include "z80disstr.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define DONE(C)         {C->status = 0; C->need = ZDAn_NONE; C->df = NULL;}
#define ERROR(C,N)      {C->status = (int8_t)N; goto ERR_;}
#define RETSTAT(C)      return (C->status)
#define RETURN(C,N)     {C->status = (int8_t)N; return N;}
#define SETSTAT(C,N)    {C->status = (int8_t)N} 

#define CB  0xCB        // 2-Byte Instruction in 'CB' group
#define DD  0xDD        // 2-Byte Instruction in 'DD' group
#define ED  0xED        // 2-Byte Instruction in 'ED' group
#define FD  0xFD        // 2-Byte Instruction in 'FD' group

static const char _comma[]      = ",";
static const char _parenL[]     = "(";
static const char _parenR[]     = ")";
static const char _regB[]       = "b";
static const char _regC[]       = "c";
static const char _regD[]       = "d";
static const char _regE[]       = "e";
static const char _regH[]       = "h";
static const char _regL[]       = "l";
static const char _regHLp[]     = "(hl)";
static const char _regA[]       = "a";
static const char _regBC[]      = "bc";
static const char _regDE[]      = "de";
static const char _regHL[]      = "hl";
static const char _regSP[]      = "sp";
static const char _regIX[]      = "ix";
static const char _regIY[]      = "iy";
static const char _tab[]        = "\t";

static const char* const _regstrs[] = {
    _regB,
    _regC,
    _regD,
    _regE,
    _regH,
    _regL,
    _regHLp,
    _regA
};

static bool _initialized;

static fmtbyte_t _fmt_byte;
static fmtword_t _fmt_word;
static bool _uc; // Upper Case

/* *** ******************************************************** *** */
/* ***                                                          *** */
/* *** Disassembly Processing Method Declarations               *** */
/* ***                                                          *** */
/* *** These 54 methods process the first instruction fetch.    *** */
/* ***                                                          *** */
/* *** ******************************************************** *** */
/* */
static void _d_2bi(zda_ctx_t * ctx);
static void _d_adcar(zda_ctx_t * ctx);
static void _d_addar(zda_ctx_t * ctx);
static void _d_addhlrp(zda_ctx_t * ctx);
static void _d_andar(zda_ctx_t * ctx);
static void _d_call(zda_ctx_t * ctx);
static void _d_callcc(zda_ctx_t * ctx);
static void _d_ccf(zda_ctx_t * ctx);
static void _d_cpar(zda_ctx_t * ctx);
static void _d_cpl(zda_ctx_t * ctx);
static void _d_daa(zda_ctx_t * ctx);
static void _d_decreg(zda_ctx_t * ctx);
static void _d_decrp(zda_ctx_t * ctx);
static void _d_di(zda_ctx_t * ctx);
static void _d_djnz(zda_ctx_t * ctx);
static void _d_ei(zda_ctx_t * ctx);
static void _d_exaf(zda_ctx_t * ctx);
static void _d_excsphl(zda_ctx_t * ctx);
static void _d_exdehl(zda_ctx_t * ctx);
static void _d_exx(zda_ctx_t * ctx);
static void _d_halt(zda_ctx_t * ctx);
static void _d_inan(zda_ctx_t * ctx);
static void _d_increg(zda_ctx_t * ctx);
static void _d_incrp(zda_ctx_t * ctx);
static void _d_jp(zda_ctx_t * ctx);
static void _d_jpcc(zda_ctx_t * ctx);
static void _d_jpchl(zda_ctx_t * ctx);
static void _d_jr(zda_ctx_t * ctx);
static void _d_jrcc(zda_ctx_t * ctx);
static void _d_ldacrp(zda_ctx_t * ctx);
static void _d_ldcnna(zda_ctx_t * ctx);
static void _d_ldcnnhl(zda_ctx_t * ctx);
static void _d_ldcrpa(zda_ctx_t * ctx);
static void _d_ldregn(zda_ctx_t * ctx);
static void _d_ldregreg(zda_ctx_t * ctx);
static void _d_ldrpnn(zda_ctx_t * ctx);
static void _d_ldsphl(zda_ctx_t * ctx);
static void _d_nop(zda_ctx_t * ctx);
static void _d_opan(zda_ctx_t * ctx);
static void _d_orar(zda_ctx_t * ctx);
static void _d_outna(zda_ctx_t * ctx);
static void _d_poprp(zda_ctx_t * ctx);
static void _d_pushrp(zda_ctx_t * ctx);
static void _d_ret(zda_ctx_t * ctx);
static void _d_retcc(zda_ctx_t * ctx);
static void _d_rla(zda_ctx_t * ctx);
static void _d_rlca(zda_ctx_t * ctx);
static void _d_rra(zda_ctx_t * ctx);
static void _d_rrca(zda_ctx_t * ctx);
static void _d_rstn(zda_ctx_t * ctx);
static void _d_sbcar(zda_ctx_t * ctx);
static void _d_scf(zda_ctx_t * ctx);
static void _d_subar(zda_ctx_t * ctx);
static void _d_xorar(zda_ctx_t * ctx);


/* *** ******************************************************** *** */
/* ***                                                          *** */
/* *** IF2 Disassembly Processing Method Declarations           *** */
/* ***                                                          *** */
/* *** These 4 methods process the 2nd instruction fetch.       *** */
/* ***                                                          *** */
/* *** ******************************************************** *** */
/* */
static void _d_cb2(zda_ctx_t * ctx);
static void _d_dd2(zda_ctx_t * ctx);
static void _d_ed2(zda_ctx_t * ctx);
static void _d_fd2(zda_ctx_t * ctx);


/** @brief Instruction Fetch 1 processing function table */
static const df_t _dis_fntbl[] = {
    _d_nop,         // 0x00 -           nop
    _d_ldrpnn,      // 0x01 n n -       ld      rp,nn [bc]
    _d_ldcrpa,      // 0x02 -           ld      (rp),a [bc]
    _d_incrp,       // 0x03 -           inc     rp [bc]
    _d_increg,      // 0x04 -           inc     r [b]
    _d_decreg,      // 0x05 -           dec     r [b]
    _d_ldregn,      // 0x06 n -         ld      r,n [b]
    _d_rlca,        // 0x07 -           rlca
    _d_exaf,        // 0x08 -           ex      af,af'
    _d_addhlrp,     // 0x09 -           add     hl,rp [bc]
    _d_ldacrp,      // 0x0a -           ld      a,(rp) [bc]
    _d_decrp,       // 0x0b -           dec     rp [bc]
    _d_increg,      // 0x0c -           inc     r [c]
    _d_decreg,      // 0x0d -           dec     r [c]
    _d_ldregn,      // 0x0e n -         ld      r,n [c]
    _d_rrca,        // 0x0f -           rrca
    _d_djnz,        // 0x10 dis -       djnz    dis
    _d_ldrpnn,      // 0x11 n n -       ld      rp,nn [de]
    _d_ldcrpa,      // 0x12 -           ld      (rp),a [de]
    _d_incrp,       // 0x13 -           inc     rp [de]
    _d_increg,      // 0x14 -           inc     r [d]
    _d_decreg,      // 0x15 -           dec     r [d]
    _d_ldregn,      // 0x16 n -         ld      r,n [d]
    _d_rla,         // 0x17             rla
    _d_jr,          // 0x18 dis -       jr      dis
    _d_addhlrp,     // 0x19 -           add     hl,rp [de]
    _d_ldacrp,      // 0x1a -           ld      a,(rp) [de]
    _d_decrp,       // 0x1b -           dec     rp [de]
    _d_increg,      // 0x1c -           inc     r [e]
    _d_decreg,      // 0x1d -           dec     r [e]
    _d_ldregn,      // 0x1e n -         ld      r,n [e]
    _d_rra,         // 0x0f -           rra
    _d_jrcc,        // 0x20 dis -       jr      cc,dis [nz]
    _d_ldrpnn,      // 0x21 n n -       ld      rp,nn [hl]
    _d_ldcnnhl,     // 0x22 n n -       ld      (nn),hl
    _d_incrp,       // 0x23 -           inc     rp [hl]
    _d_increg,      // 0x24 -           inc     r [h]
    _d_decreg,      // 0x25 -           dec     r [h]
    _d_ldregn,      // 0x26 n -         ld      r,n [h]
    _d_daa,         // 0x27 -           daa
    _d_jrcc,        // 0x28 dis -       jr      cc,dis [z]
    _d_addhlrp,     // 0x29 -           add     hl,rp [hl]
    _d_ldacrp,      // 0x2a -           ld      a,(rp) [hl]
    _d_decrp,       // 0x2b -           dec     rp [hl]
    _d_increg,      // 0x2c -           inc     r [l]
    _d_decreg,      // 0x2d -           dec     r [l]
    _d_ldregn,      // 0x2e n -         ld      r,n [l]
    _d_cpl,         // 0x2f -           cpl
    _d_jrcc,        // 0x30 dis -       jr      cc,dis [nc]
    _d_ldrpnn,      // 0x31 n n -       ld      rp,nn [sp]
    _d_ldcnna,      // 0x32 n n -       ld      (nn),a
    _d_incrp,       // 0x33 -           inc     rp [sp]
    _d_increg,      // 0x34 -           inc     r [(hl)]
    _d_decreg,      // 0x35 -           dec     r [(hl)]
    _d_ldregn,      // 0x36 n -         ld      r,n [(hl)]
    _d_scf,         // 0x37             scf
    _d_jrcc,        // 0x38 dis -       jr      cc,dis [c]
    _d_addhlrp,     // 0x39 -           add     hl,rp [sp]
    _d_ldacrp,      // 0x3a n n -       ld      a,(nn)
    _d_decrp,       // 0x3b -           dec     rp [sp]
    _d_increg,      // 0x3c -           inc     r [a]
    _d_decreg,      // 0x3d -           dec     r [a]
    _d_ldregn,      // 0x3e n -         ld      r,n [a]
    _d_ccf,         // 0x3f -           ccf
    _d_ldregreg,    // 0x40 -           ld      r,r [b][b]
    _d_ldregreg,    // 0x41 -           ld      r,r [b][c]
    _d_ldregreg,    // 0x42 -           ld      r,r [b][d]
    _d_ldregreg,    // 0x43 -           ld      r,r [b][e]
    _d_ldregreg,    // 0x44 -           ld      r,r [b][h]
    _d_ldregreg,    // 0x45 -           ld      r,r [b][l]
    _d_ldregreg,    // 0x46 -           ld      r,r [b][(hl)]
    _d_ldregreg,    // 0x47 -           ld      r,r [b][a]
    _d_ldregreg,    // 0x48 -           ld      r,r [c][b]
    _d_ldregreg,    // 0x49 -           ld      r,r [c][c]
    _d_ldregreg,    // 0x4a -           ld      r,r [c][d]
    _d_ldregreg,    // 0x4b -           ld      r,r [c][e]
    _d_ldregreg,    // 0x4c -           ld      r,r [c][h]
    _d_ldregreg,    // 0x4d -           ld      r,r [c][l]
    _d_ldregreg,    // 0x4e -           ld      r,r [c][(hl)]
    _d_ldregreg,    // 0x4f -           ld      r,r [c][a]
    _d_ldregreg,    // 0x50 -           ld      r,r [d][b]
    _d_ldregreg,    // 0x51 -           ld      r,r [d][c]
    _d_ldregreg,    // 0x52 -           ld      r,r [d][d]
    _d_ldregreg,    // 0x53 -           ld      r,r [d][e]
    _d_ldregreg,    // 0x54 -           ld      r,r [d][h]
    _d_ldregreg,    // 0x55 -           ld      r,r [d][l]
    _d_ldregreg,    // 0x56 -           ld      r,r [d][(hl)]
    _d_ldregreg,    // 0x57 -           ld      r,r [d][a]
    _d_ldregreg,    // 0x58 -           ld      r,r [e][b]
    _d_ldregreg,    // 0x59 -           ld      r,r [e][c]
    _d_ldregreg,    // 0x5a -           ld      r,r [e][d]
    _d_ldregreg,    // 0x5b -           ld      r,r [e][e]
    _d_ldregreg,    // 0x5c -           ld      r,r [e][h]
    _d_ldregreg,    // 0x5d -           ld      r,r [e][l]
    _d_ldregreg,    // 0x5e -           ld      r,r [e][(hl)]
    _d_ldregreg,    // 0x5f -           ld      r,r [e][a]
    _d_ldregreg,    // 0x60 -           ld      r,r [h][b]
    _d_ldregreg,    // 0x61 -           ld      r,r [h][c]
    _d_ldregreg,    // 0x62 -           ld      r,r [h][d]
    _d_ldregreg,    // 0x63 -           ld      r,r [h][e]
    _d_ldregreg,    // 0x64 -           ld      r,r [h][h]
    _d_ldregreg,    // 0x65 -           ld      r,r [h][l]
    _d_ldregreg,    // 0x66 -           ld      r,r [h][(hl)]
    _d_ldregreg,    // 0x67 -           ld      r,r [h][a]
    _d_ldregreg,    // 0x68 -           ld      r,r [l][b]
    _d_ldregreg,    // 0x69 -           ld      r,r [l][c]
    _d_ldregreg,    // 0x6a -           ld      r,r [l][d]
    _d_ldregreg,    // 0x6b -           ld      r,r [l][e]
    _d_ldregreg,    // 0x6c -           ld      r,r [l][h]
    _d_ldregreg,    // 0x6d -           ld      r,r [l][l]
    _d_ldregreg,    // 0x6e -           ld      r,r [l][(hl)]
    _d_ldregreg,    // 0x6f -           ld      r,r [l][a]
    _d_ldregreg,    // 0x70 -           ld      r,r [(hl)][b]
    _d_ldregreg,    // 0x71 -           ld      r,r [(hl)][c]
    _d_ldregreg,    // 0x72 -           ld      r,r [(hl)][d]
    _d_ldregreg,    // 0x73 -           ld      r,r [(hl)][e]
    _d_ldregreg,    // 0x74 -           ld      r,r [(hl)][h]
    _d_ldregreg,    // 0x75 -           ld      r,r [(hl)][l]
    _d_halt,        // 0x76 -           halt
    _d_ldregreg,    // 0x77 -           ld      r,r [(hl)][a]
    _d_ldregreg,    // 0x78 -           ld      r,r [a][b]
    _d_ldregreg,    // 0x79 -           ld      r,r [a][c]
    _d_ldregreg,    // 0x7a -           ld      r,r [a][d]
    _d_ldregreg,    // 0x7b -           ld      r,r [a][e]
    _d_ldregreg,    // 0x7c -           ld      r,r [a][h]
    _d_ldregreg,    // 0x7d -           ld      r,r [a][l]
    _d_ldregreg,    // 0x7e -           ld      r,r [a][(hl)]
    _d_ldregreg,    // 0x7f -           ld      r,r [a][a]
    _d_addar,       // 0x80 -           add     a,r [b]
    _d_addar,       // 0x81 -           add     a,r [c]
    _d_addar,       // 0x82 -           add     a,r [d]
    _d_addar,       // 0x83 -           add     a,r [e]
    _d_addar,       // 0x84 -           add     a,r [h]
    _d_addar,       // 0x85 -           add     a,r [l]
    _d_addar,       // 0x86 -           add     a,r [(hl)]
    _d_addar,       // 0x87 -           add     a,r [a]
    _d_adcar,       // 0x88 -           adc     a,r [b]
    _d_adcar,       // 0x89 -           adc     a,r [c]
    _d_adcar,       // 0x8a -           adc     a,r [d]
    _d_adcar,       // 0x8b -           adc     a,r [e]
    _d_adcar,       // 0x8c -           adc     a,r [h]
    _d_adcar,       // 0x8d -           adc     a,r [l]
    _d_adcar,       // 0x8e -           adc     a,r [(hl)]
    _d_adcar,       // 0x8f -           adc     a,r [a]
    _d_subar,       // 0x90 -           sub     r [b]
    _d_subar,       // 0x91 -           sub     r [c]
    _d_subar,       // 0x92 -           sub     r [d]
    _d_subar,       // 0x93 -           sub     r [e]
    _d_subar,       // 0x94 -           sub     r [h]
    _d_subar,       // 0x95 -           sub     r [l]
    _d_subar,       // 0x96 -           sub     r [(hl)]
    _d_subar,       // 0x97 -           sub     r [a]
    _d_sbcar,       // 0x98 -           sbc     a,r [b]
    _d_sbcar,       // 0x98 -           sbc     a,r [c]
    _d_sbcar,       // 0x9a -           sbc     a,r [d]
    _d_sbcar,       // 0x9b -           sbc     a,r [e]
    _d_sbcar,       // 0x9c -           sbc     a,r [h]
    _d_sbcar,       // 0x9d -           sbc     a,r [l]
    _d_sbcar,       // 0x9e -           sbc     a,r [(hl)]
    _d_sbcar,       // 0x9f -           sbc     a,r [a]
    _d_andar,       // 0xa0 -           and     r [b]
    _d_andar,       // 0xa1 -           and     r [c]
    _d_andar,       // 0xa2 -           and     r [d]
    _d_andar,       // 0xa3 -           and     r [e]
    _d_andar,       // 0xa4 -           and     r [h]
    _d_andar,       // 0xa5 -           and     r [l]
    _d_andar,       // 0xa6 -           and     r [(hl)]
    _d_andar,       // 0xa7 -           and     r [a]
    _d_xorar,       // 0xa8 -           xor     r [b]
    _d_xorar,       // 0xa9 -           xor     r [c]
    _d_xorar,       // 0xaa -           xor     r [d]
    _d_xorar,       // 0xab -           xor     r [e]
    _d_xorar,       // 0xac -           xor     r [h]
    _d_xorar,       // 0xad -           xor     r [l]
    _d_xorar,       // 0xae -           xor     r [(hl)]
    _d_xorar,       // 0xaf -           xor     r [a]
    _d_orar,        // 0xb0 -           or      r [b]
    _d_orar,        // 0xb1 -           or      r [c]
    _d_orar,        // 0xb2 -           or      r [d]
    _d_orar,        // 0xb3 -           or      r [e]
    _d_orar,        // 0xb4 -           or      r [h]
    _d_orar,        // 0xb5 -           or      r [l]
    _d_orar,        // 0xb6 -           or      r [(hl)]
    _d_orar,        // 0xb7 -           or      r [a]
    _d_cpar,        // 0xb8 -           cp      r [b]
    _d_cpar,        // 0xb9 -           cp      r [c]
    _d_cpar,        // 0xba -           cp      r [d]
    _d_cpar,        // 0xbb -           cp      r [e]
    _d_cpar,        // 0xbc -           cp      r [h]
    _d_cpar,        // 0xbd -           cp      r [l]
    _d_cpar,        // 0xbe -           cp      r [(hl)]
    _d_cpar,        // 0xbf -           cp      r [a]
    _d_retcc,       // 0xc0 -           ret     cc [nz]
    _d_poprp,       // 0xc1 -           pop     rp [bc]
    _d_jpcc,        // 0xc2 n n -       jp      cc,nn [nz]
    _d_jp,          // 0xc3 n n -       jp      nn
    _d_callcc,      // 0xc4 n n -       call    cc,nn [nz]
    _d_pushrp,      // 0xc5 -           push    rp [bc]
    _d_opan,        // 0xc6 n -         add     a,n
    _d_rstn,        // 0xc7 -           rst     n [00h](0)
    _d_retcc,       // 0xc8 -           ret     cc [z]
    _d_ret,         // 0xc9 -           ret
    _d_jpcc,        // 0xca n n -       jp      cc,nn [z]
    _d_2bi,         // 0xcb * -         * IF1 = CB (handle 2-byte instruction)
    _d_callcc,      // 0xcc n n -       call    cc,nn [z]
    _d_call,        // 0xcd n n -       call    nn
    _d_opan,        // 0xce n -         adc     a,n
    _d_rstn,        // 0xcf -           rst     n [08h](1)
    _d_retcc,       // 0xd0 -           ret     cc [nc]
    _d_poprp,       // 0xd1 -           pop     rp [de]
    _d_jpcc,        // 0xd2 n n -       jp      cc,nn [nc]
    _d_outna,       // 0xd3 n -         out     (n),a
    _d_callcc,      // 0xd4 n n -       call    cc,nn [nc]
    _d_pushrp,      // 0xd5 -           push    rp [de]
    _d_opan,        // 0xd6 n -         sub     n
    _d_rstn,        // 0xd7 -           rst     n [10h](2)
    _d_retcc,       // 0xd8 -           ret     cc [c]
    _d_exx,         // 0xd9 -           exx
    _d_jpcc,        // 0xda n n -       jp      cc,nn [c]
    _d_inan,        // 0xdb n -         in      a,(n)
    _d_callcc,      // 0xdc n n -       call    cc,nn [c]
    _d_2bi,         // 0xdd * -         * IF1 = DD (handle 2-byte instruction)
    _d_opan,        // 0xde n -         sbc     a,n
    _d_rstn,        // 0xdf -           rst     n [18h](3)
    _d_retcc,       // 0xe0 -           ret     cc [po]
    _d_poprp,       // 0xe1 -           pop     rp [hl]
    _d_jpcc,        // 0xe2 n n -       jp      cc,nn [po]
    _d_excsphl,     // 0xe3 -           ex      (sp),hl
    _d_callcc,      // 0xe4 n n -       call    cc,nn [po]
    _d_pushrp,      // 0xe5 -           push    rp [hl]
    _d_opan,        // 0xe6 -           and     n
    _d_rstn,        // 0xe7 -           rst     n [20h](4)
    _d_retcc,       // 0xe8 -           ret     cc [pe]
    _d_jpchl,       // 0xe9 -           jp      (hl)
    _d_jpcc,        // 0xea n n -       jp      cc,nn [pe]
    _d_exdehl,      // 0xeb -           ex      de,hl
    _d_callcc,      // 0xec n n -       call    cc,nn [pe]
    _d_2bi,         // 0xed * -         * IF1 = ED (handle 2-byte instruction)
    _d_opan,        // 0xee n -         xor     n
    _d_rstn,        // 0xef -           rst     n [28](5)
    _d_retcc,       // 0xf0 -           ret     cc [p]
    _d_poprp,       // 0xf1 -           pop     rp [af]
    _d_jpcc,        // 0xf2 n n -       jp      cc,nn [p]
    _d_di,          // 0xf3 -           di
    _d_callcc,      // 0xf4 n n -       call    cc,nn [p]
    _d_pushrp,      // 0xf5 -           push    rp [af]
    _d_opan,        // 0xf6 n -         or      n
    _d_rstn,        // 0xf7 -           rst     n [30h](6)
    _d_retcc,       // 0xf8 -           ret     cc [m]
    _d_ldsphl,      // 0xf9 -           ld      sp,hl
    _d_jpcc,        // 0xfa n n -       jp      cc,nn [m]
    _d_ei,          // 0xfb -           ei
    _d_callcc,      // 0xfc n n -       call    cc,nn [m]
    _d_2bi,         // 0xfd * -         * IF1 = FD (handle 2-byte instruction)
    _d_opan,        // 0xfe n -         cp      n
    _d_rstn,        // 0xff -           rst     n [38h](7)
};


/* *** ******************************************************** *** */
/* ***                                                          *** */
/* *** Disassembly utility/helper methods                       *** */
/* ***                                                          *** */
/* *** ******************************************************** *** */

/**
 * @brief Concatenate string `s` to buffer conditionally uppercasing.
 * 
 * @param buf Buffer 
 * @param s String
 * @param uc Upper Case if true
 * @return int the number of characters advanced
 */
static int _strcat(char* buf, const char* s, bool uc) {
    int n = strlen(buf);
    char c,u;
    while ((c = *s++)) {
        u = (uc ? toupper(c) : c);
        *(buf+n) = u;
        n++;
    }
    return n;
}

/**
 * @brief Concatenate a TAB STR to a buffer
 * 
 * @param buf The buffer to concatenate into
 * @param s A string
 * @param uc Upper Case if true
 * @return int The number of bytes the buffer was advanced (including any bytes skipped)
 */
static int _catts(char* buf, const char* s, bool uc) {
    int n = _strcat(buf, _tab, uc);
    n += _strcat(buf+n, s, uc);
    return n;
}

/**
 * @brief Concatenate a STR TAB STR to a buffer
 *
 * @param buf The buffer to concatenate into
 * @param s1 String 1
 * @param s2 String 2
 * @param uc Upper Case if true
 * @return int The number of bytes the buffer was advanced (including any bytes skipped)
 */
static int _catsts(char* buf, const char* s1, const char* s2, bool uc) {
    int n = _strcat(buf, s1, uc);
    n += _catts(buf+n, s2, uc);
    return n;
}

/**
 * @brief Concatenate a TAB STR STR to a buffer
 * 
 * @param buf The buffer to concatenate into
 * @param s1 String 1
 * @param s2 String 2
 * @param uc Upper Case if true
 * @return int The number of bytes the buffer was advanced (including any bytes skipped)
 */
static int _cattss(char* buf, const char* s1, const char* s2, bool uc) {
    int n = _catts(buf, s1, uc);
    n += _strcat(buf+n, s2, uc);
    return n;
}

/**
 * @brief Concatenate a TAB STR COMMA STR to a buffer using Instruction Register 2
 * 
 * Register 2 pulls from bits 2..0 of the instruction
 * 
 * @param buf The buffer to concatenate into 
 * @param s1 String 1
 * @param s2 String 2
 * @return int The number of bytes the buffer was advanced (including any bytes skipped)
 */
static int _cattscs(char* buf, const char* s1, const char* s2) {
    int n = _cattss(buf, s1, _comma, _uc);
    n += _strcat(buf+n, s2, _uc); 
    return n;
}

static int _cattrcnr(char* buf, const char* r, uint8_t rn) {
    const char* reg2 = _regstrs[rn];
    int n = _cattscs(buf, r, reg2);
    return n;
}

/**
 * @brief Get the register number from the instruction using formula 1
 * 
 * Formula 1:
 *  reg# = bits 5..3 from the instruction opcode
 * 
 * @param inst The instruction byte to derive the register from
 * @return uint8_t Register number 0 to 7
 */
static uint8_t _regn1(uint8_t inst) {
    return ((inst & 0b00111000) >> 3);
}

/**
 * @brief Get the register number from the instruction using formula 2
 *
 * Formula 2:
 *  reg# = bits 2..0 from the instruction opcode
 *
 * @param inst The instruction byte to derive the register from
 * @return uint8_t Register number 0 to 7
 */
static uint8_t _regn2(uint8_t inst) {
    return (inst & 0b00000111);
}

static int _cattrcrn1(char* buf, const char* r, uint8_t inst) {
    const char* r2 = _regstrs[_regn1(inst)];
    int n = _cattscs(buf, r, r2);
    return n;
}

static int _cattrcrn2(char* buf, const char* r, uint8_t inst) {
    const char* r2 = _regstrs[_regn2(inst)];
    int n = _cattscs(buf, r, r2);
    return n;
}

static int _inst_t_r_c_rn2(char* buf, const char* istr, const char* r, uint8_t inst) {
    int n = _strcat(buf, istr, _uc);
    n += _cattrcrn2(buf + n, _regA, inst);
    return n;
}

/* *** ******************************************************** *** */
/* ***                                                          *** */
/* *** Disassembly IF1 processing methods                       *** */
/* ***                                                          *** */
/* *** ******************************************************** *** */

/**
 * @brief Start disassembly of a 2-byte instruction (CB,DD,ED,FD)
 *
 * The context contains the first byte. Set up for the 2nd.
 */
static void _d_2bi(zda_ctx_t* ctx) {
    ctx->need = ZDAn_IF2;
    ctx->status = 1;            // At least one more byte is needed
    switch (ctx->d[0]) {
    case CB:
        ctx->df = _d_cb2;   // Process CB 2nd IF
        break;
    case DD:
        ctx->df = _d_dd2;   // Process DD 2nd IF
        break;
    case ED:
        ctx->df = _d_ed2;   // Process ED 2nd IF
        break;
    case FD:
        ctx->df = _d_fd2;   // Process FD 2nd IF
        break;
    default:
        ctx->status = ZDAE_UNKNOWN;
        ctx->df = NULL;
    }
}

/** @brief ADC  a,r */
static void _d_adcar(zda_ctx_t* ctx) {
    _inst_t_r_c_rn2(ctx->inst, zdp_ADC, _regA, ctx->d[0]);
    DONE(ctx);
}

static void _d_addar(zda_ctx_t* ctx) {
    _inst_t_r_c_rn2(ctx->inst, zdp_ADD, _regA, ctx->d[0]);
    DONE(ctx);
}

static void _d_addhlrp(zda_ctx_t* ctx) {
}

static void _d_andar(zda_ctx_t* ctx) {
}

static void _d_call(zda_ctx_t* ctx) {
}

static void _d_callcc(zda_ctx_t* ctx) {
}

static void _d_ccf(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_CCF, _uc);
    DONE(ctx);
}

static void _d_cpar(zda_ctx_t* ctx) {
}

static void _d_cpl(zda_ctx_t* ctx) {
}

static void _d_daa(zda_ctx_t* ctx) {
}

static void _d_decreg(zda_ctx_t* ctx) {
}

static void _d_decrp(zda_ctx_t* ctx) {
}

static void _d_di(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_DI, _uc);
    DONE(ctx);
}

static void _d_djnz(zda_ctx_t* ctx) {
}

static void _d_ei(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_EI, _uc);
    DONE(ctx);
}

static void _d_exaf(zda_ctx_t* ctx) {
}

static void _d_excsphl(zda_ctx_t* ctx) {
}

static void _d_exdehl(zda_ctx_t* ctx) {
}

static void _d_exx(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_EXX, _uc);
    DONE(ctx);
}

static void _d_halt(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_HALT, _uc);
    DONE(ctx);
}

static void _d_inan(zda_ctx_t* ctx) {
}

static void _d_increg(zda_ctx_t* ctx) {
}

static void _d_incrp(zda_ctx_t* ctx) {
}

static void _d_jp(zda_ctx_t* ctx) {
}

static void _d_jpcc(zda_ctx_t* ctx) {
}

static void _d_jpchl(zda_ctx_t* ctx) {
}

static void _d_jr(zda_ctx_t* ctx) {
}

static void _d_jrcc(zda_ctx_t* ctx) {
}

static void _d_ldacrp(zda_ctx_t* ctx) {
}

static void _d_ldcnna(zda_ctx_t* ctx) {
}

static void _d_ldcnnhl(zda_ctx_t* ctx) {
}

static void _d_ldcrpa(zda_ctx_t* ctx) {
}

static void _d_ldregn(zda_ctx_t* ctx) {
}

static void _d_ldregreg(zda_ctx_t* ctx) {
}

static void _d_ldrpnn(zda_ctx_t* ctx) {
}

static void _d_ldsphl(zda_ctx_t* ctx) {
}

/**
 * @brief NOP - No Operation
 */
static void _d_nop(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_NOP, _uc);
    DONE(ctx);
}

static void _d_opan(zda_ctx_t* ctx) {
}

static void _d_orar(zda_ctx_t* ctx) {
}

static void _d_outna(zda_ctx_t* ctx) {
}

static void _d_poprp(zda_ctx_t* ctx) {
}

static void _d_pushrp(zda_ctx_t* ctx) {
}

static void _d_ret(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_RET, _uc);
    DONE(ctx);
}

static void _d_retcc(zda_ctx_t* ctx) {
}

static void _d_rla(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_RLA, _uc);
    DONE(ctx);
}

static void _d_rlca(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_RLCA, _uc);
    DONE(ctx);
}

static void _d_rra(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_RRA, _uc);
    DONE(ctx);
}

static void _d_rrca(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_RRCA, _uc);
    DONE(ctx);
}

static void _d_rstn(zda_ctx_t* ctx) {
    char buf[ZDA_FMT_BYTE_BUF_LEN];
    uint8_t n = ctx->d[0] & 0x38; // opcode & 00111000 is the RST address
    _fmt_byte(buf, n);
    _catsts(ctx->inst, zdp_RST, buf, _uc);
    sprintf(ctx->comment, "%d", (n >> 3));
    DONE(ctx);
}

static void _d_sbcar(zda_ctx_t* ctx) {
}

static void _d_scf(zda_ctx_t* ctx) {
    _strcat(ctx->inst, zdp_SCF, _uc);
    DONE(ctx);
}

static void _d_subar(zda_ctx_t* ctx) {
}

static void _d_xorar(zda_ctx_t* ctx) {
}


/* *** ******************************************************** *** */
/* ***                                                          *** */
/* *** Disassembly IF2 processing methods                       *** */
/* ***                                                          *** */
/* *** ******************************************************** *** */

/**
 * Disassemble 'CB' group byte-2
 *
 * (Context assumed valid)
 */
static void _d_cb2(zda_ctx_t* ctx) {

}

/**
 * Disassemble 'DD' group byte-2
 *
 * (Context assumed valid)
 */
static void _d_dd2(zda_ctx_t* ctx) {

}

/**
 * Disassemble 'ED' group byte-2
 *
 * (Context assumed valid)
 */
static void _d_ed2(zda_ctx_t* ctx) {

}

/**
 * Disassemble 'FD' group byte-2
 *
 * (Context assumed valid)
 */
static void _d_fd2(zda_ctx_t* ctx) {

}


/**
 * Disassemble with this being the first byte
 * 
 * (Context assumed valid)
 */
static void _dis_b1(zda_ctx_t* ctx) {
    // Use byte-1 to index into the function table.
    uint8_t b1 = ctx->d[0];
    const df_t df = _dis_fntbl[b1];
    df(ctx);
    return;
}

static void _disassemble(zda_ctx_t* ctx) {
    if (!ctx->df) ERROR(ctx, ZDAE_DF_NULL);
    ctx->df(ctx);

ERR_:
    return;
}

int8_t zda_begin(zda_ctx_t* ctx, uint16_t addr, uint8_t data) {
    if (!_initialized) ERROR(ctx, ZDAE_UNINITIALIZED);
    memset(ctx, 0, sizeof(zda_ctx_t));
    ctx->addr = addr;
    ctx->d[ctx->bi++] = data;
    ctx->df = _dis_b1;
    _disassemble(ctx);

ERR_:
    RETSTAT(ctx);
}

int8_t zda_next(zda_ctx_t* ctx, uint8_t data) {
    // sanity check context
    if (ctx->status < 0) goto FINALLY_;
    if (ctx->status == ZDA_DONE) ERROR(ctx,ZDAE_UNNEEDED);
    if (ctx->bi >= Z80INST_MAX_BYTES) ERROR(ctx,ZDAE_TOO_MANY_BYTES);
    ctx->d[ctx->bi] = data;
    _disassemble(ctx);

ERR_:
FINALLY_:
    RETSTAT(ctx);
}

void zda_unknown(zda_ctx_t* ctx) {
    // Create the instruction and comment content for an unknown instruction
    char buf[ZDA_FMT_BYTE_BUF_LEN];

    strcpy(ctx->comment, "Unknown instruction");
    strcpy(ctx->inst, "?=");
    for (int i = 0; i < ctx->bi; i++) {
        _fmt_byte(buf, ctx->d[i]);
        _strcat(ctx->inst, buf, _uc);
        if (i < (ctx->bi - 1)) {
            _strcat(ctx->inst, ",", _uc);
        }
    }
}

int zda_modinit(fmtbyte_t byte_formatter, fmtword_t word_formatter, bool upper_case) {
    int retval = 0;

    if (!byte_formatter) {
        retval = 1;
        goto FINALLY_;
    }
    if (!word_formatter) {
        retval = 2;
        goto FINALLY_;
    }
    _fmt_byte = byte_formatter;
    _fmt_word = word_formatter;
    _uc = upper_case;

    _initialized = true;

FINALLY_:
    return retval;
}
