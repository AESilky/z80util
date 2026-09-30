/**
 * @brief Test for the Z80 Disassembler Module
 * @file main.c
 * 
 * This calls the Z80 Disassembler for either:
 * 1. All Z80 instructions and some illegal instructions
 * 2. Just the instruction groups specified on the command line
 *   1 = Single Byte instructions
 *   C = 2-byte CB instructions
 *   D = 2-byte DD instructions
 *   E = 2-byte ED instructions
 *   F = 2-byte FD instructions
 *   I = Illegal instructions (a few in 2-byte groups)
 * 3. Instruction opcode bytes specified on the command line (in hex)
 *   X hh hh hh ...
 * 
 * Copyright 2026 AESilky
 * SPDX-License-Identifier: MIT License
 */
#include "z80disasm.h"  // The Disassembler methods
#include "z80allbin.h"  // add instructions binary data

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void _fmt_byte(char* buf, uint8_t v) {
    sprintf(buf, "%02x", v);
}

static void _fmt_byteh(char* buf, uint8_t v) {
    sprintf(buf, "%02xh", v);
}

static void _fmt_word(char* buf, uint16_t v) {
    sprintf(buf, "%04x", v);
}

unsigned int uint_from_hexstr(const char* str, bool* success) {
    char* unparsed;
    *success = true; // Be an optimist
    unsigned long retval = strtoul(str, &unparsed, 16);
    if (*unparsed) {
        retval = 0;
        *success = false;
    }
    return (retval);
}

static void _list_inst(zda_ctx_t* ctx) {
    static int line = 1;               // Used for listing output
    char buf[3];
    char *comment = (*(ctx->comment) ? "\t\t; " : "");
    printf("%4d %04X ", line++, ctx->addr);
    for (int i = 0; i < Z80INST_MAX_BYTES; i++) {
        const char* db = "  ";
        if (i < ctx->bi) {
            _fmt_byte(buf, ctx->d[i]);
            db = buf;
        }
        printf("%s ", db);
    }
    printf("%s%s%s\n", ctx->stmt, comment, ctx->comment);
}

static void _usage(const char* name) {
    printf("usage: %s [(-h|--help)|(X nn nn ...)|[1][C][D][E][F][I]]\n", name);
    printf(" 1 : 1-Byte instructions\n");
    printf(" C : 2-byte 'CB' instructions\n");
    printf(" D : 2-byte 'DD' instructions\n");
    printf(" E : 2-byte 'ED' instructions\n");
    printf(" F : 2-byte 'FD' instructions\n");
    printf(" I : Illegal instructions\n");
    printf(" X nn nn ... : Opcodes provided as hex byte values\n");
    printf(" -u or --upper : Uppercase disassembly output (must be before 'X' if used)\n");
    printf(" -h or --help : Print this.\n");
    printf(" If no parameters are specified all instruction groups including invalid are used.\n");
}

static void _opt_err(const char* name) {
    fprintf(stderr, "Invalid option.\n");
    _usage(name);
}

int main(int argc, char** argv){
    const char* name = *argv++; argc--;
    uint16_t addr = 0;          // Used for disassembly
    int ds; // Disassembler status
    size_t elements; // Element count for the instruction groups
    bool uc = false;

    // Do all if no arguments were given
    bool b1;    // Single-byte instructions
    bool cb;    // CB group 2-byte instructions
    bool dd;    // DD group 2-byte instructions
    bool ed;    // ED group 2-byte instructions
    bool fd;    // FD group 2-byte instructions
    bool ig;    // Illegal (2-byte) instructions
    bool xb = false;    // Assume the groups will be used
    b1 = cb = dd = ed = fd = ig = (argc > 1 ? false : true);

    while (argc > 0) {
        char opt;
        char* opts = *(argv);
        argv++; argc--;
        while ((opt = *opts)) {
            switch (opt) {
                case '1':
                    b1 = true;
                    break;
                case 'C':
                    cb = true;
                    break;
                case 'D':
                    dd = true;
                    break;
                case 'E':
                    ed = true;
                    break;
                case 'F':
                    fd = true;
                    break;
                case 'I':
                    ig = true;
                    break;
                case 'X':
                    b1 = cb = dd = ed = fd = ig = false; // If bytes specified, don't do groups
                    xb = true;
                    goto OPTSEND_;
                case '-':
                    // check for "-u" or "--upper"
                    if (strcmp(opts, "-u") == 0 || strcmp(opts, "--upper") == 0) {
                        uc = true;
                        // skip to next arg;
                        while(*opts) opts++;
                        continue;
                    }
                    // check for "-h" or "--help"
                    if (strcmp(opts, "-h") != 0 && strcmp(opts, "--help") != 0) {
                        _opt_err(name);
                        goto ERR_RET_;
                    }
                    _usage(name);
                    goto FINALLY_;
                default:
                    _opt_err(name);
                    goto ERR_RET_;
            }
            opts++;
        }
    }
OPTSEND_:
    // Initialize the Disassembler
    ds = zda_modinit(_fmt_byteh, _fmt_word, uc);
    if (ds != 0) {
        fprintf(stderr, "Disassembler init error: %s\n", ds);
        goto ERR_RET_;
    }
    if (b1) {
        printf("Single Byte Instructions...\n");
        elements = z1b_len();
        for (int i = 0; i < elements; i++) {
            printf("%02X\n", *(z80_1byte + i));
        }
    }
    if (cb) {
        printf("\nTwo Byte 'CB' Instructions...\n");
        elements = z2bCB_len();
        for (int i = 0; i < elements; i++) {
            printf("%02X\n", *(z80_2byteCB + i));
        }
    }
    if (dd) {
        printf("\nTwo Byte 'DD' Instructions...\n");
        elements = z2bDD_len();
        for (int i = 0; i < elements; i++) {
            printf("%02X\n", *(z80_2byteDD + i));
        }
    }
    if (ed) {
        printf("\nTwo Byte 'ED' Instructions...\n");
        elements = z2bED_len();
        for (int i = 0; i < elements; i++) {
            printf("%02X\n", *(z80_2byteED + i));
        }
    }
    if (fd) {
        printf("\nTwo Byte 'FD' Instructions...\n");
        elements = z2bFD_len();
        for (int i = 0; i < elements; i++) {
            printf("%02X\n", *(z80_2byteFD + i));
        }
    }
    if (ig) {
        printf("\nInvalid Instructions...\n");
        elements = zInvalid_len();
        for (int i = 0; i < elements; i++) {
            printf("%02X\n", *(z80_invalid + i));
        }
    }
    if (xb) {
        // Use the rest of the arguments as hex bytes
        //
        // First, run through them all to make sure they are valid
        for (int i = 0; i < argc; i++) {
            bool success;
            unsigned int b = uint_from_hexstr(*(argv + i), &success);
            if (!success || b > 255) {
                fprintf(stderr, "The argument '%s' is not a valid hex byte\n", *argv);
                goto ERR_RET_;
            }
        }
        zda_ctx_t ctx;
        // Okay, they are all valid hex bytes. Start calling the disassemble.
        for (int i = 0; i < argc; i++) {
            bool success;
            unsigned int b = uint_from_hexstr(*(argv + i), &success);
            // no need to check success - all arguments were checked above
            int8_t s = zda_begin(&ctx, addr, b);
            if (s == 0) {
                goto NEXT_;
            }
            while (s > 0 && ++i < argc) {
                // feed the disassembler additional bytes
                // s indicates the minimum needed, but we only feed one at a time
                addr++; // move to next address
                b = uint_from_hexstr(*(argv + i), &success);
                s = zda_next(&ctx, b);
            }
            if (s < 0 || i >= argc) {
                // There was a problem.
                if (s < 0) {
                    fprintf(stderr, "Disassembler indicated error: %d\n", s);
                    goto ERR_RET_;
                }
                if (i >= argc) {
                    fprintf(stderr, "Not enough byte values provided. Need at least %d more.\n", s);
                    goto ERR_RET_;
                }
            }
        NEXT_:
            // s is 0, list the disassembly
            _list_inst(&ctx);
            addr++;
        }
    }
FINALLY_:
    printf("DONE\n");
    return 0;
ERR_RET_:
    return 1;
}
