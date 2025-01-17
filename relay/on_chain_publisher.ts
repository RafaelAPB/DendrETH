import { ProofResultType } from './types/types';
import { IBeaconApi } from './abstraction/beacon-api-interface';
import { IRedis } from './abstraction/redis-interface';
import { ISmartContract } from './abstraction/smart-contract-abstraction';
import { Contract } from 'ethers';
import {
  TransactionSpeed,
  getSolidityProof,
  publishTransaction,
} from './implementations/publish_evm_transaction';
import Web3 from 'web3';
import { sleep } from '../libs/typescript/ts-utils/common-utils';

let isDrainRunning = false;

export async function publishProofs(
  redis: IRedis,
  beaconApi: IBeaconApi,
  smartContract: ISmartContract,
  hashiAdapterContract: Contract | undefined,
  rpcEndpoint: string,
  transactionSpeed: TransactionSpeed = 'avg',
) {
  try {
    await drainUpdatesInRedis(
      redis,
      beaconApi,
      smartContract,
      hashiAdapterContract,
      rpcEndpoint,
      transactionSpeed,
    );

    await redis.subscribeForProofs(async () => {
      try {
        await drainUpdatesInRedis(
          redis,
          beaconApi,
          smartContract,
          hashiAdapterContract,
          rpcEndpoint,
          transactionSpeed,
        );
      } catch (e) {
        console.error('Error while draining updates in Redis', e);
      }
    });
  } catch (error) {
    console.error('Error occurred while publishing proofs: ', error);
    throw error;
  }
}

export async function drainUpdatesInRedis(
  redis: IRedis,
  beaconApi: IBeaconApi,
  smartContract: ISmartContract,
  hashiAdapterContract: Contract | undefined,
  rpcEndpoint: string,
  transactionSpeed: TransactionSpeed = 'avg',
) {
  if (isDrainRunning) {
    console.log('Publishing transactions is already running');
    return;
  }
  isDrainRunning = true;
  let failedNumber = 0;
  while (true) {
    try {
      const header_root_on_chain = await smartContract.optimisticHeaderRoot();

      console.log('header on chain', header_root_on_chain);

      const lastSlotOnChain = await beaconApi.getBlockSlot(
        header_root_on_chain,
      );

      const proofResult = await redis.getNextProof(lastSlotOnChain);

      if (proofResult == null) {
        isDrainRunning = false;
        return;
      }

      try {
        await postUpdateOnChain(
          proofResult,
          smartContract,
          beaconApi,
          lastSlotOnChain,
          hashiAdapterContract,
          rpcEndpoint,
          transactionSpeed,
        );
        // Slow down broadcasting
        await sleep(2000);
        failedNumber = 0;
      } catch (error) {
        [failedNumber, isDrainRunning] = (await handleFailure(
          error,
          'publishing transaction',
          failedNumber,
        )) as any[];
      }
    } catch (error) {
      [failedNumber, isDrainRunning] = (await handleFailure(
        error,
        'fetching header',
        failedNumber,
      )) as any[];
    }
  }
}

export async function postUpdateOnChain(
  proofResult: ProofResultType,
  lightClientContract: ISmartContract,
  beaconApi: IBeaconApi,
  lastSlotOnChain: number,
  hashiAdapterContract: Contract | undefined,
  rpcEndpoint: string,
  transactionSpeed: TransactionSpeed = 'avg',
) {
  const update = {
    attestedHeaderRoot:
      '0x' +
      BigInt('0b' + proofResult.proofInput.nextHeaderHash.join(''))
        .toString(16)
        .padStart(64, '0'),
    attestedHeaderSlot: proofResult.proofInput.nextHeaderSlot,
    finalizedHeaderRoot:
      '0x' +
      BigInt('0b' + proofResult.proofInput.finalizedHeaderRoot.join(''))
        .toString(16)
        .padStart(64, '0'),
    finalizedExecutionStateRoot:
      '0x' +
      BigInt('0b' + proofResult.proofInput.execution_state_root.join(''))
        .toString(16)
        .padStart(64, '0'),
  };

  console.log(update);

  if (hashiAdapterContract) {
    const hashiInfo = await beaconApi.getHashiAdapterInfo(
      proofResult.proofInput.nextHeaderSlot,
    );

    const solidityProof = await getSolidityProof({
      a: proofResult.proof.pi_a,
      b: proofResult.proof.pi_b,
      c: proofResult.proof.pi_c,
    });

    await publishTransaction(
      hashiAdapterContract,
      'storeBlockHeader(uint32,uint64,uint256,bytes32[],bytes32,bytes32[],(bytes32,uint256,bytes32,bytes32,uint256[2],uint256[2][2],uint256[2]))',
      [
        (await hashiAdapterContract.provider.getNetwork()).chainId,
        proofResult.proofInput.nextHeaderSlot,
        hashiInfo.blockNumber,
        hashiInfo.blockNumberProof.map(x => '0x' + x),
        '0x' + hashiInfo.blockHash,
        hashiInfo.blockHashProof.map(x => '0x' + x),
        { ...update, ...solidityProof },
      ],
      new Web3(rpcEndpoint),
      transactionSpeed,
      true,
    );
  } else {
    await lightClientContract.postUpdateOnChain({
      ...update,
      a: proofResult.proof.pi_a,
      b: proofResult.proof.pi_b,
      c: proofResult.proof.pi_c,
    });
  }

  const transactionSlot = proofResult.proofInput.nextHeaderSlot;

  const currentHeadSlot = await beaconApi.getCurrentHeadSlot();

  console.log(`Previous slot on the chain ${lastSlotOnChain}`);

  console.log(`Transaction publishing for slot ${transactionSlot}`);

  console.log(`Current slot on the network is ${currentHeadSlot}`);

  console.log(
    `Prev slot is ${
      ((currentHeadSlot - lastSlotOnChain) * 12) / 60
    } minutes behind`,
  );

  console.log(
    `Transaction is ${
      ((currentHeadSlot - transactionSlot) * 12) / 60
    } minutes behind`,
  );
}

async function handleFailure(
  error: any,
  scopeError: string,
  failedNumber: number,
): Promise<[number, boolean]> {
  if (failedNumber > 10) {
    log(error, `ERROR occurred in ${scopeError}`, 'STOPPING');
    isDrainRunning = false;
    return [failedNumber, isDrainRunning];
  }
  log(error, `ERROR occurred in ${scopeError}`, 'will retry');
  failedNumber++;
  await sleep(10000);

  return [failedNumber, isDrainRunning];
}

function log(error: any, firstMessage: string, secondMessage: string): void {
  console.log(firstMessage);
  console.log(error);
  console.log(secondMessage);
}
