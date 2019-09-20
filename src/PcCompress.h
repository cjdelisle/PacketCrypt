/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef PCCOMPRESS_H
#define PCCOMPRESS_H

#include "PacketCryptProof.h" // Entry_t

#include <stdint.h>
#include <stdbool.h>

enum {
    // constants
    PcCompress_F_COMPUTABLE =   1,
    PcCompress_F_PAD_ENTRY =   (1<<1),
    PcCompress_F_LEAF =        (1<<2),
    PcCompress_F_RIGHT =       (1<<3),

    PcCompress_F_PAD_SIBLING = (1<<4),
    PcCompress_F_FIRST_ENTRY = (1<<5), // 0x20


    // manipulated by PacketCryptProof.c
    PcCompress_F_HAS_HASH =    (1<<8),
    PcCompress_F_HAS_RANGE =   (1<<9),
    PcCompress_F_HAS_START =   (1<<10)
};

typedef struct {
    uint16_t childLeft;
    uint16_t childRight;

    // If parent is UINT16_MAX then this is the root entry
    uint16_t parent;

    uint16_t flags;

    Entry_t e;
} PcCompress_Entry_t;
_Static_assert(sizeof(PcCompress_Entry_t) == 8+sizeof(Entry_t), "");

#define PcCompress_HAS_ALL(x, flags) (((x) & (flags)) == (flags))

typedef struct {
    int branchHeight;
    int count;
    PcCompress_Entry_t entries[];
} PcCompress_t;
_Static_assert(sizeof(PcCompress_t) == 8, "");

PcCompress_t* PcCompress_mkEntryTable(
    uint64_t annCount,
    const uint64_t annNumbers[static PacketCrypt_NUM_ANNS]
);

PcCompress_Entry_t* PcCompress_getRoot(PcCompress_t* tbl);

PcCompress_Entry_t* PcCompress_getAnn(PcCompress_t* tbl, uint64_t annNum);

PcCompress_Entry_t* PcCompress_getParent(PcCompress_t* tbl, PcCompress_Entry_t* e);

PcCompress_Entry_t* PcCompress_getSibling(PcCompress_t* tbl, PcCompress_Entry_t* e);

bool PcCompress_hasExplicitRange(PcCompress_Entry_t* e);

#endif
