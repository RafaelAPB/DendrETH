import { Queue } from 'bullmq';
import { GetUpdate } from '../types/types';
import { Config } from '../constants/constants';
import {
  SLOTS_PER_PERIOD,
  computeSyncCommitteePeriodAt,
} from '../../libs/typescript/ts-utils/ssz-utils';
import { IBeaconApi } from '../abstraction/beacon-api-interface';
import { findClosestValidBlock } from '../workers/poll-updates/get_light_client_input_from_to';

export async function addUpdate(
  optimisticSlot: number,
  slotsJump: number,
  headSlot: number,
  updateQueue: Queue<GetUpdate>,
  networkConfig: Config,
  beaconApi: IBeaconApi,
): Promise<boolean> {
  const jobsInQueueSortedByFrom = (await updateQueue.getJobs()).sort(
    (a, b) => a.data.from - b.data.from,
  );

  for (let i = 0; i < jobsInQueueSortedByFrom.length; i++) {
    // skip failed jobs
    if (await jobsInQueueSortedByFrom[i].isFailed()) continue;

    if (jobsInQueueSortedByFrom[i].data.from === optimisticSlot) {
      optimisticSlot = jobsInQueueSortedByFrom[i].data.to;
    }
  }

  const nextSlot = await getNextSlot(
    optimisticSlot,
    slotsJump,
    headSlot,
    beaconApi,
  );

  if (optimisticSlot >= nextSlot) {
    console.log('Not new enough slot');
    return false;
  }

  console.log('New update from to added');

  await updateQueue.add(
    'update',
    {
      from: optimisticSlot,
      to: nextSlot,
      networkConfig: networkConfig,
    },
    {
      attempts: 10,
      backoff: {
        type: 'fixed',
        delay: 15000,
      },
      priority: optimisticSlot,
    },
  );

  return true;
}

async function getNextSlot(
  slot: number,
  slotsJump: number,
  headSlot: number,
  beaconApi: IBeaconApi,
) {
  const periodAtSlot = computeSyncCommitteePeriodAt(slot);
  const periodAtHeadSlot = computeSyncCommitteePeriodAt(headSlot);

  if (periodAtSlot + 1 >= periodAtHeadSlot) {
    // next slot will be the closest multiple of slotsJump to headSlot
    const potentialNewSlot = headSlot - (headSlot % slotsJump);

    const result = await findClosestValidBlock(
      potentialNewSlot,
      beaconApi,
      headSlot,
    );

    return result.nextBlockHeader.slot;
  }

  // next slot will be the first slot of the last epoch of the next period
  const potentialNewSlot =
    (periodAtSlot + 1) * SLOTS_PER_PERIOD + (SLOTS_PER_PERIOD - 32);

  const result = await findClosestValidBlock(
    potentialNewSlot,
    beaconApi,
    headSlot,
  );

  return result.nextBlockHeader.slot;
}