# RandomHash

A hash function which changes based on the input

**NOTE:** This is not a secure hash function, it's a primitive for building something
larger, do not use it unless you know what you're doing.

## Why

If you use a hash function to hash a password (for example), someone who wants to figure
out your password and they happen to have the hash (from a hacked website for instance),
their best bet is to try to guess different passwords and try to hash them and compare to
the output.

With technology like GPUs (video cards), people can make thousands of guesses at the same
time because GPUs have powerful parallel processors. The way that GPUs are able to be so
effective at simple repetitive jobs like cracking passwords is because of
[SIMD](https://en.wikipedia.org/wiki/SIMD).

GPUs in particular have the ability to perform the same operation on an enormous number of
different pieces of data at the same time, and if that operation is a hash function, then
they can guess a lot of passwords really quickly.

RandomHash attempts to frustrate parallel cracking attempts by creating a wholly different
hash function for every password.

## How
https://github.com/cjdelisle/RandomHash/blob/master/src/randhash.c
There is a code generator in [RandGen.c](https://github.com/cjdelisle/RandomHash/blob/master/RandGen.c)
which generates a bytecode language from a random seed and a set of parameters. Then there
are two programs which are able to consume this bytecode, one is an interpreter
([Interpreter.c](https://github.com/cjdelisle/RandomHash/blob/master/Interpreter.c)) and the
other is a generator of C code ([PrintProg.c](https://github.com/cjdelisle/RandomHash/blob/master/PrintProg.c)).

PrintProg ouputs a preprocessor-heavy C program such as the following:

```c
char* RANDHASH_SEED = "2";
#include "prelude.h"
BEGIN
LOOP(loop_1, 3) { // 0x00300042 @ 0
  OP1(l_1_1, MEMORY(loop_1, 0x000044d8, 9, 11)); // 0x89b13641 @ 1
  OP1(l_1_2, MEMORY(loop_1, 0x000044d8, 9, 8)); // 0x89b13041 @ 2
  OP1(l_1_3, MEMORY(loop_1, 0x000044d8, 9, 11)); // 0x89b13641 @ 3
  OP1(l_1_4, IN(7)); // 0x27a9e440 @ 4
  OP1(l_1_5, ROTL32(l_1_4, l_1_2)); // 0x0020081d @ 5
  OP1(l_1_6, CLZ8(l_1_5)); // 0x00000a04 @ 6
  LOOP(loop_2, 22) { // 0x01600042 @ 7
    OP1(l_2_1, MEMORY(loop_2, 0x00003293, 3, 2)); // 0x65266441 @ 8
    OP1(l_2_2, MEMORY(loop_2, 0x00003293, 3, 3)); // 0x65266641 @ 9
    OP1(l_2_3, MEMORY(loop_2, 0x00003293, 3, 7)); // 0x65266e41 @ 10
    OP1(l_2_4, XOR(l_2_2, l_2_3)); // 0x00a01223 @ 11
    OP1(l_2_5, IN(3)); // 0xa4b0b740 @ 12
    OP2(l_2_6, l_2_7, MULU8C(l_1_6, l_2_5)); // 0x00c00c30 @ 13
    OP1(l_2_8, CTZ16(l_2_4)); // 0x00001608 @ 14
    LOOP(loop_3, 2) { // 0x00200042 @ 15
      OP1(l_3_1, MEMORY(loop_3, 0x0000504d, 12, 11)); // 0xa09b9741 @ 16
      OP1(l_3_2, MEMORY(loop_3, 0x0000504d, 12, 4)); // 0xa09b8941 @ 17
      OP1(l_3_3, IN(7)); // 0xde8ab140 @ 18
      OP1(l_3_4, IN(5)); // 0x9755cf40 @ 19
      OP1(l_3_5, IN(7)); // 0xddd89640 @ 20
      OP1(l_3_6, SHRL8(l_3_2, 0x000000cd)); // 0x0cd42415 @ 21
      OP2(l_3_7, l_3_8, MULSU16C(l_3_6, l_3_5)); // 0x01502c2e @ 22
      OP4(l_3_9, l_3_10, l_3_11, l_3_12, SUB64C(l_2_6, l_2_7, l_3_3, l_3_4)); // 0x01401c3c @ 23
      OP4(l_3_13, l_3_14, l_3_15, l_3_16, ADD64C(l_2_5, l_2_6, 0x000001c9, 0x00000000)); // 0x1c941a3b @ 24
      IF_LIKELY(l_1_6) { // 0x00200c43 @ 25
        OP1(l_4_1, IN(0)); // 0xec830e40 @ 27
        OP1(l_4_2, IN(7)); // 0x1b765740 @ 28
        OUT2(l_4_1, l_4_2);
      } // 0x00000046 @ 29
      else { // 0x00000545 @ 30
        OP1(l_4_1, OR(l_3_7, l_2_1)); // 0x00802e22 @ 31
        OP1(l_4_2, SHRL16(l_4_1, l_2_8)); // 0x00f04416 @ 32
        OP1(l_4_3, AND(l_4_2, l_4_2)); // 0x02304621 @ 33
        OP2(l_4_4, l_4_5, ROTR64(l_4_1, l_4_2, 0x000006fb, 0x00000000)); // 0x6fb44639 @ 34
        OUT4(l_4_1, l_4_2, l_4_3, l_4_4);
        OUT(l_4_5);
      } // 0x00000046 @ 35
      OP1(l_3_17, IN(3)); // 0x74322a40 @ 36
      OP1(l_3_18, CLZ8(l_2_8)); // 0x00001e04 @ 37
      OP1(l_3_19, IN(7)); // 0xa78a6d40 @ 38
      OP1(l_3_20, POPCNT8(l_3_8)); // 0x00003001 @ 39
      OP1(l_3_21, SUB32(l_1_3, l_3_9)); // 0x01900611 @ 40
      OP1(l_3_22, CLZ16(l_3_10)); // 0x00003405 @ 41
      OP2(l_3_23, l_3_24, MUL64(l_2_2, l_2_3, l_2_3, l_2_4)); // 0x00b0143a @ 42
      OP1(l_3_25, BSWAP32(l_3_14)); // 0x00003c0b @ 43
      OP1(l_3_26, IN(7)); // 0xad2a6540 @ 44
      IF_RANDOM(l_3_17) { // 0x00204244 @ 45
        OP1(l_4_1, IN(0)); // 0x1c035640 @ 47
        OP1(l_4_2, ADD32(l_2_1, l_4_1)); // 0x02c0100e @ 48
        OP2(l_4_3, l_4_4, MUL64(l_3_11, l_3_12, l_4_1, l_4_2)); // 0x02d0383a @ 49
        OP1(l_4_5, POPCNT32(l_4_3)); // 0x00005c03 @ 50
        OP2(l_4_6, l_4_7, MUL64(l_3_15, l_3_16, 0x000004bf, 0x00000000)); // 0x4bf4403a @ 51
        OP1(l_4_8, IN(5)); // 0xa0d7a540 @ 52
        IF_LIKELY(l_4_8) { // 0x00206643 @ 53
          OP1(l_5_1, IN(6)); // 0x80fe1a40 @ 55
          OP1(l_5_2, CLZ16(l_4_2)); // 0x00005a05 @ 56
          OP1(l_5_3, IN(7)); // 0x085f7e40 @ 57
          OP1(l_5_4, CLZ16(l_5_1)); // 0x00006a05 @ 58
          OP1(l_5_5, POPCNT32(l_5_2)); // 0x00006c03 @ 59
          OP2(l_5_6, l_5_7, ADD8C(l_4_4, l_4_6)); // 0x03105e24 @ 60
          OP2(l_5_8, l_5_9, ADD8C(l_5_3, l_4_5)); // 0x03006e24 @ 61
          OP2(l_5_10, l_5_11, MUL16C(l_5_4, 0xfffffb57)); // 0xb574702b @ 62
          OP2(l_5_12, l_5_13, ADD64(l_5_7, l_5_8, l_5_9, l_5_10)); // 0x03e07833 @ 63
          OP1(l_5_14, POPCNT32(l_5_5)); // 0x00007203 @ 64
          OP4(l_5_15, l_5_16, l_5_17, l_5_18, MULU64C(l_4_6, l_4_7, l_4_7, l_4_8)); // 0x0330643f @ 65
          OP1(l_5_19, IN(7)); // 0x3f4ebe40 @ 66
          OP1(l_5_20, CTZ8(l_3_1)); // 0x00002207 @ 67
          OP1(l_5_21, CLZ16(l_4_3)); // 0x00005c05 @ 68
          OP2(l_5_22, l_5_23, MULSU16C(l_5_19, l_4_8)); // 0x03308e2e @ 69
          OP2(l_5_24, l_5_25, SHRA64(l_4_6, l_4_7, 0xfffffd66, 0xffffffff)); // 0xd6646437 @ 70
          OP2(l_5_26, l_5_27, MULSU8C(l_5_1, l_5_6)); // 0x03a06a2d @ 71
          OP1(l_5_28, POPCNT16(l_5_20)); // 0x00009002 @ 72
          OP2(l_5_29, l_5_30, ROTR64(l_4_1, l_4_2, l_5_12, l_5_13)); // 0x04105a39 @ 73
          OP1(l_5_31, SHRL32(l_5_24, l_5_25)); // 0x04d09817 @ 74
          OP4(l_5_32, l_5_33, l_5_34, l_5_35, MULU64C(l_5_14, l_5_15, 0x0000053d, 0x00000000)); // 0x53d4863f @ 75
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
          OUT8(l_5_9, l_5_10, l_5_11, l_5_12, l_5_13, l_5_14, l_5_15, l_5_16);
          OUT8(l_5_17, l_5_18, l_5_19, l_5_20, l_5_21, l_5_22, l_5_23, l_5_24);
          OUT8(l_5_25, l_5_26, l_5_27, l_5_28, l_5_29, l_5_30, l_5_31, l_5_32);
          OUT2(l_5_33, l_5_34);
          OUT(l_5_35);
        } // 0x00000046 @ 76
        else { // 0x00000c45 @ 77
          OP4(l_5_1, l_5_2, l_5_3, l_5_4, ADD64C(l_4_7, l_4_8, 0x00000707, 0x00000000)); // 0x7074663b @ 78
          OP1(l_5_5, ADD16(l_5_1, l_5_2)); // 0x03606a0d @ 79
          OP2(l_5_6, l_5_7, ADD8C(l_2_4, l_5_4)); // 0x03801624 @ 80
          OP1(l_5_8, CTZ8(l_5_6)); // 0x00007407 @ 81
          OP2(l_5_9, l_5_10, MUL64(l_5_4, l_5_5, l_4_6, l_4_7)); // 0x0320723a @ 82
          OP1(l_5_11, ROTL32(l_5_10, l_5_7)); // 0x03b07c1d @ 83
          OP1(l_5_12, CTZ32(l_4_1)); // 0x00005809 @ 84
          OP2(l_5_13, l_5_14, SHRA64(l_5_11, l_5_12, 0x000002f7, 0x00000000)); // 0x2f748037 @ 85
          OP4(l_5_15, l_5_16, l_5_17, l_5_18, SUB64C(l_5_13, l_5_14, l_5_1, l_5_2)); // 0x0360843c @ 86
          OP2(l_5_19, l_5_20, SHLL64(l_5_8, l_5_9, 0x0000058c, 0x00000000)); // 0x58c47a35 @ 87
          OP2(l_5_21, l_5_22, ADD16C(l_5_17, l_5_15)); // 0x04308a25 @ 88
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
          OUT8(l_5_9, l_5_10, l_5_11, l_5_12, l_5_13, l_5_14, l_5_15, l_5_16);
          OUT4(l_5_17, l_5_18, l_5_19, l_5_20);
          OUT2(l_5_21, l_5_22);
        } // 0x00000046 @ 89
        OP1(l_4_9, IN(7)); // 0x78dea840 @ 90
        OP2(l_4_10, l_4_11, SHRL64(l_3_11, l_3_12, 0x0000021a, 0x00000000)); // 0x21a43836 @ 91
        OP1(l_4_12, IN(3)); // 0xae2c7c40 @ 92
        OP2(l_4_13, l_4_14, SUB32C(l_4_12, l_4_9)); // 0x03406e29 @ 93
        OP4(l_4_15, l_4_16, l_4_17, l_4_18, MULU64C(l_3_18, l_3_19, l_4_13, l_4_14)); // 0x0390463f @ 94
        OP1(l_4_19, POPCNT32(l_4_15)); // 0x00007403 @ 95
        OP1(l_4_20, POPCNT8(l_4_16)); // 0x00007601 @ 96
        IF_LIKELY(l_4_10) { // 0x00206a43 @ 97
          OP2(l_5_1, l_5_2, MULU8C(l_4_11, 0xfffff9c4)); // 0x9c446c30 @ 99
          OP4(l_5_3, l_5_4, l_5_5, l_5_6, MULU64C(l_5_1, l_5_2, 0xfffffcfe, 0xffffffff)); // 0xcfe4843f @ 100
          OP2(l_5_7, l_5_8, MULSU32C(l_5_3, l_5_4)); // 0x0440862f @ 101
          IF_LIKELY(l_4_9) { // 0x00206843 @ 102
            OP1(l_6_1, IN(0)); // 0xc9853140 @ 104
            OP1(l_6_2, IN(7)); // 0xfddeb140 @ 105
            OP1(l_6_3, CTZ32(l_6_1)); // 0x00009409 @ 106
            OUT2(l_6_1, l_6_2);
            OUT(l_6_3);
          } // 0x00000046 @ 107
          else { // 0x00000445 @ 108
            OP1(l_6_1, IN(7)); // 0x88de6140 @ 109
            OP1(l_6_2, BSWAP16(l_6_1)); // 0x0000940a @ 110
            OP1(l_6_3, IN(1)); // 0x2690f740 @ 111
            OUT2(l_6_1, l_6_2);
            OUT(l_6_3);
          } // 0x00000046 @ 112
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
        } // 0x00000046 @ 113
        else { // 0x00001245 @ 114
          OP1(l_5_1, IN(6)); // 0xc17bf440 @ 115
          OP1(l_5_2, IN(1)); // 0xeb173e40 @ 116
          OP1(l_5_3, POPCNT32(l_5_2)); // 0x00008403 @ 117
          OP1(l_5_4, SHLL32(l_5_3, l_3_13)); // 0x01d08614 @ 118
          OP1(l_5_5, POPCNT32(l_5_4)); // 0x00008803 @ 119
          OP1(l_5_6, AND(l_5_1, l_4_16)); // 0x03b08221 @ 120
          OP2(l_5_7, l_5_8, ROTL64(l_4_4, l_4_5, l_5_5, l_5_6)); // 0x04606038 @ 121
          OP2(l_5_9, l_5_10, SHRL64(l_5_6, l_5_7, l_5_2, l_5_3)); // 0x04308e36 @ 122
          OP4(l_5_11, l_5_12, l_5_13, l_5_14, MUL64C(l_5_7, l_5_8, l_5_5, l_5_6)); // 0x0460903d @ 123
          OP1(l_5_15, BSWAP32(l_5_9)); // 0x0000920b @ 124
          IF_LIKELY(l_4_19) { // 0x00207c43 @ 125
            OP1(l_6_1, CLZ32(l_5_15)); // 0x00009e06 @ 127
            OUT(l_6_1);
          } // 0x00000046 @ 128
          else { // 0x00000245 @ 129
            OP1(l_6_1, POPCNT16(l_5_10)); // 0x00009402 @ 130
            OUT(l_6_1);
          } // 0x00000046 @ 131
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
          OUT4(l_5_9, l_5_10, l_5_11, l_5_12);
          OUT2(l_5_13, l_5_14);
          OUT(l_5_15);
        } // 0x00000046 @ 132
        OUT8(l_4_1, l_4_2, l_4_3, l_4_4, l_4_5, l_4_6, l_4_7, l_4_8);
        OUT8(l_4_9, l_4_10, l_4_11, l_4_12, l_4_13, l_4_14, l_4_15, l_4_16);
        OUT4(l_4_17, l_4_18, l_4_19, l_4_20);
      } // 0x00000046 @ 133
      else { // 0x00003a45 @ 134
        OP1(l_4_1, IN(7)); // 0xfdf5a340 @ 135
        OP1(l_4_2, CTZ8(l_4_1)); // 0x00005807 @ 136
        OP2(l_4_3, l_4_4, SHLL64(l_4_1, l_4_2, l_4_1, l_4_2)); // 0x02d05a35 @ 137
        OP4(l_4_5, l_4_6, l_4_7, l_4_8, MULSU64C(l_4_3, l_4_4, l_3_20, l_3_21)); // 0x02505e3e @ 138
        OP1(l_4_9, POPCNT16(l_4_6)); // 0x00006202 @ 139
        IF_LIKELY(l_4_2) { // 0x00205a43 @ 140
          OP1(l_5_1, IN(7)); // 0x90ee1140 @ 142
          OP1(l_5_2, SHRA16(l_5_1, l_4_9)); // 0x03406c19 @ 143
          OP1(l_5_3, POPCNT32(l_5_2)); // 0x00006e03 @ 144
          OP2(l_5_4, l_5_5, ADD64(l_5_1, l_5_2, l_5_1, l_5_2)); // 0x03706e33 @ 145
          OP1(l_5_6, SHRL32(l_5_3, l_5_4)); // 0x03907017 @ 146
          OP2(l_5_7, l_5_8, SUB16C(l_5_5, l_5_6)); // 0x03b07428 @ 147
          OP2(l_5_9, l_5_10, ROTL64(l_5_2, l_5_3, 0x00000081, 0x00000000)); // 0x08147038 @ 148
          OP2(l_5_11, l_5_12, MULSU16C(l_2_8, 0xfffffc67)); // 0xc6741e2e @ 149
          IF_LIKELY(l_5_8) { // 0x00207a43 @ 150
            OP1(l_6_1, IN(1)); // 0x1f93bb40 @ 152
            OP1(l_6_2, IN(3)); // 0x67312f40 @ 153
            OP1(l_6_3, CLZ32(l_6_1)); // 0x00008606 @ 154
            OP1(l_6_4, SHLL32(l_6_2, l_6_2)); // 0x04408814 @ 155
            OUT4(l_6_1, l_6_2, l_6_3, l_6_4);
          } // 0x00000046 @ 156
          else { // 0x00000545 @ 157
            OP1(l_6_1, IN(7)); // 0x35739940 @ 158
            OP1(l_6_2, IN(6)); // 0xf2e47d40 @ 159
            OP1(l_6_3, CTZ16(l_3_22)); // 0x00004c08 @ 160
            OP1(l_6_4, IN(7)); // 0x489fdd40 @ 161
            OUT4(l_6_1, l_6_2, l_6_3, l_6_4);
          } // 0x00000046 @ 162
          OP1(l_5_13, IN(5)); // 0xa7d11a40 @ 163
          OP2(l_5_14, l_5_15, ROTR64(l_5_12, l_5_13, l_5_9, l_5_10)); // 0x03f08439 @ 164
          OP2(l_5_16, l_5_17, SHRL64(l_5_13, l_5_14, l_4_2, l_4_3)); // 0x02e08636 @ 165
          OP1(l_5_18, CTZ16(l_5_2)); // 0x00006e08 @ 166
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
          OUT8(l_5_9, l_5_10, l_5_11, l_5_12, l_5_13, l_5_14, l_5_15, l_5_16);
          OUT2(l_5_17, l_5_18);
        } // 0x00000046 @ 167
        else { // 0x00000f45 @ 168
          OP4(l_5_1, l_5_2, l_5_3, l_5_4, SUB64C(l_4_7, l_4_8, l_2_7, l_2_8)); // 0x00f0663c @ 169
          OP1(l_5_5, CTZ8(l_5_2)); // 0x00006e07 @ 170
          OP1(l_5_6, AND(l_5_5, l_5_2)); // 0x03707421 @ 171
          OP2(l_5_7, l_5_8, SHLL64(l_5_3, l_5_4, l_5_1, l_5_2)); // 0x03707235 @ 172
          OP4(l_5_9, l_5_10, l_5_11, l_5_12, MUL64C(l_5_6, l_5_7, l_5_6, l_5_7)); // 0x03c0783d @ 173
          OP1(l_5_13, SUB32(l_5_10, l_4_5)); // 0x03007e11 @ 174
          OP4(l_5_14, l_5_15, l_5_16, l_5_17, MULU64C(l_5_8, l_5_9, 0xfffffa37, 0xffffffff)); // 0xa3747c3f @ 175
          OP1(l_5_18, SHRL8(l_5_11, 0xfffffb72)); // 0xb7248015 @ 176
          OP1(l_5_19, SHLL32(l_5_12, l_2_8)); // 0x00f08214 @ 177
          IF_RANDOM(l_5_18) { // 0x00208e44 @ 178
          } // 0x00000046 @ 180
          else { // 0x00000145 @ 181
          } // 0x00000046 @ 182
          OUT8(l_5_1, l_5_2, l_5_3, l_5_4, l_5_5, l_5_6, l_5_7, l_5_8);
          OUT8(l_5_9, l_5_10, l_5_11, l_5_12, l_5_13, l_5_14, l_5_15, l_5_16);
          OUT2(l_5_17, l_5_18);
          OUT(l_5_19);
        } // 0x00000046 @ 183
        LOOP(loop_5, 11) { // 0x00b00042 @ 184
          OP1(l_5_1, MEMORY(loop_5, 0x00003f06, 10, 4)); // 0x7e0d4841 @ 185
          OP1(l_5_2, MEMORY(loop_5, 0x00003f06, 10, 5)); // 0x7e0d4a41 @ 186
          OP1(l_5_3, IN(1)); // 0xe412cf40 @ 187
          OP2(l_5_4, l_5_5, ADD32C(l_2_2, l_5_1)); // 0x03601226 @ 188
          OP1(l_5_6, POPCNT8(l_5_3)); // 0x00007001 @ 189
          OP1(l_5_7, CLZ32(l_5_2)); // 0x00006e06 @ 190
          OUT4(l_5_1, l_5_2, l_5_3, l_5_4);
          OUT2(l_5_5, l_5_6);
          OUT(l_5_7);
        } // 0x00000046 @ 191
        OUT8(l_4_1, l_4_2, l_4_3, l_4_4, l_4_5, l_4_6, l_4_7, l_4_8);
        OUT(l_4_9);
      } // 0x00000046 @ 192
      LOOP(loop_4, 85) { // 0x05500042 @ 193
        OP1(l_4_1, MEMORY(loop_4, 0x00004afd, 4, 11)); // 0x95fa9741 @ 194
        OP1(l_4_2, ADD8(l_4_1, l_4_1)); // 0x02c0580c @ 195
        OP2(l_4_3, l_4_4, SUB8C(l_4_2, l_4_2)); // 0x02d05a27 @ 196
        OUT4(l_4_1, l_4_2, l_4_3, l_4_4);
      } // 0x00000046 @ 197
      OUT8(l_3_1, l_3_2, l_3_3, l_3_4, l_3_5, l_3_6, l_3_7, l_3_8);
      OUT8(l_3_9, l_3_10, l_3_11, l_3_12, l_3_13, l_3_14, l_3_15, l_3_16);
      OUT8(l_3_17, l_3_18, l_3_19, l_3_20, l_3_21, l_3_22, l_3_23, l_3_24);
      OUT2(l_3_25, l_3_26);
    } // 0x00000046 @ 198
    OUT8(l_2_1, l_2_2, l_2_3, l_2_4, l_2_5, l_2_6, l_2_7, l_2_8);
  } // 0x00000046 @ 199
  OUT4(l_1_1, l_1_2, l_1_3, l_1_4);
  OUT2(l_1_5, l_1_6);
} // 0x00000046 @ 200
END
```

#### Instructions
Arithmatic instructions have 4 variants for treating 8 bit, 16 bit, 32 bit and 64 bit numbers.
If ADD8 for instance will add each 8 bit section of argument one to each 8 bit section of
argument 2. Arithmatic instructions also have a variant which returns two outputs, a value
and a "carry", for addition, carry is a 1 if the number rolls over when adding, for
multiplication is is the high bits of the result.

* One argument instructions, one output
    * POPCNT count the number of bits which are set in the input value
        * POPCNT8
        * POPCNT16
        * POPCNT32
    * CLZ count the number of leading zeros in the input value
        * CLZ8
        * CLZ16
        * CLZ32
    * CLZ count the number of *trailing* zeros in the input
        * CTZ8
        * CTZ16
        * CTZ32
    * BSWAP16 swap the high and low bytes of each 16 bit half of the value
    * BSWAP32 swap value from big endian to little endian or the reverse
* Two argument instructions, one output
    * ADD add without carry (number rolls over)
        * ADD8
        * ADD16
        * ADD32
    * SUB subtract without carry
        * SUB8
        * SUB16
        * SUB32
    * SHLL shift left logical (unsigned)
        * SHLL8
        * SHLL16
        * SHLL32
    * SHRL shift right logical (unsigned)
        * SHRL8
        * SHRL16
        * SHRL32
    * SHRA shift right arithmatic (signed, extends the sign bit)
        * SHRA8
        * SHRA16
        * SHRA32
    * ROTL rotate left
        * ROTL8
        * ROTL16
        * ROTL32
    * MUL multiply without carry
        * MUL8
        * MUL16
        * MUL32
    * AND logical AND
    * OR logical OR
    * XOR logical XOR
* Two argument instructions with 2 outputs
    * ADDC add values and output the result and a carry value
        * ADD8C
        * ADD16C
        * ADD32C
    * SUBC subtract and carry
        * SUB8C
        * SUB16C
        * SUB32C
    * MULC multiply signed*signed and carry
        * MUL8C
        * MUL16C
        * MUL32C
    * MULSUC multiply signed*unsigned and carry
        * MULSU8C
        * MULSU16C
        * MULSU32C
    * MULUC multiply unsigned*unsigned and carry
        * MULU8C
        * MULU16C
        * MULU32C
* 64 bit instructions with one 64 bit output
    * ADD64
    * SUB64
    * SHLL64
    * SHRL64
    * SHRA64
    * ROTL64
    * ROTR64
    * MUL64
* 64 bit instructions with two 64 bit outputs
    * ADD64C
    * SUB64C
    * MUL64C
    * MULSU64C
    * MULU64C
* Control instructions
    * IN reads a word from the input hash
    * MEMORY reads a value from memory, this is used with LOOP to stream memory
    * LOOP repeat a set of instructions n times
    * IF_LIKELY branch with a 87.5% chance that it will be taken
    * IF_RANDOM branch with a 50% chance that it will be taken
    * JMP unconditional jump (used with IF to implement the "else" block)
    * END end a scope (LOOP, IF)

### Design considerations
1. There are instructions taken from modern CPUs processors as well as from ARM NEON
and AVX vector instructions in order that hardware designed to run RandomHash efficiently
is likely to also be useful as a general purpose CPU.
2. There is liberal use of loops and branches in order to encourage research in branch
prediction and speculative execution as well as efficient register allocation.