/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
/*@flow*/
/*::
import type { Master_Config_t } from './Master.js'
import type { AnnHandler_Config_t } from './AnnHandler.js'
import type { BlkHandler_Config_t } from './BlkHandler.js'
import type { Rpc_Config_t } from './Rpc.js'
import type { PayMaker_Config_t } from './PayMaker.js'

export type Config_t = {
    masterUrl: string,
    rootWorkdir: string,
    privateSeed: string|null,
    paymakerHttpPasswd: string,
    annHandlers: Array<AnnHandler_Config_t>,
    blkHandlers: Array<BlkHandler_Config_t>,
    master: Master_Config_t,
    rpc: Rpc_Config_t,
    payMaker: PayMaker_Config_t
};
export type Config_Miner_Content_t = {
    type: number,
    val: Buffer
}
export type Config_Miner_t = {
    paymentAddr: string,
    corePath: string,
    dir: string,
    poolUrl: string,
    threads: number,
    minerId: number,
};
export type Config_BlkMiner_t = Config_Miner_t & {
    version: number,
    slowStart: bool,
    maxAnns: number,
};
export type Config_AnnMiner_t = Config_Miner_t & {
    content?: Config_Miner_Content_t,
    randContent: bool,
    version: number,
    paranoia: boolean,
    maxKbps: number,
    mineOldAnns: number|null,
}
*/
