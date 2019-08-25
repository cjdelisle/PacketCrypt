/*@flow*/
/*::
import type { Master_Config_t } from './Master.js'
import type { AnnHandler_Config_t } from './AnnHandler.js'
import type { BlkHandler_Config_t } from './BlkHandler.js'
import type { Rpc_Config_t } from './Rpc.js'

export type Config_t = {
    masterUrl: string,
    rootWorkdir: string,
    privateSeed: string,
    checkannsPath: string,
    checksharesPath: string,
    annHandlers: Array<AnnHandler_Config_t>,
    blkHandlers: Array<BlkHandler_Config_t>,
    master: Master_Config_t,
    rpc: Rpc_Config_t,
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
    maxAnns?: number,
    minerId: number,
    slowStart: bool,

    content?: Config_Miner_Content_t,
    randContent: bool
};
*/
