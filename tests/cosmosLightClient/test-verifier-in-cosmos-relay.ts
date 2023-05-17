import glob_ from 'glob';
const glob = glob_.sync;
import { promisify } from 'node:util';
import { exec as exec_ } from 'node:child_process';

import {
  setUpCosmosTestnet,
  stopCosmosNode,
} from '../../libs/typescript/cosmos-utils/testnet-setup';
import { CosmosContract } from '../../relay/implementations/cosmos-contract';
import { compileContractMain } from '../../contracts/cosmos/verifier/lib/typescript/verifier-compile-contract-and-tools';
import { getRootDir, sleep } from '../../libs/typescript/ts-utils/common-utils';
import {
  instantiateVerifierContract,
  uploadVerifierContract,
} from '../../contracts/cosmos/verifier/lib/typescript/verifier-upload-instantiate';
import { replaceInTextProof } from '../helpers/helpers';
import { readFileSync } from 'fs';

const exec = promisify(exec_);

describe('Light Client Verifier In Cosmos', () => {
  let contractDirVerifier: string;
  let parseDataTool: string;
  let pathToVerifyUtils: string;
  let updateFiles: string[];
  let cosmosContract: CosmosContract;
  let DendrETHWalletInfo;
  let cosmos;

  let controller = new AbortController();
  const { signal } = controller;

  const rpcEndpoint = 'http://localhost:26657';
  const mnemonic =
    'economy stock theory fatal elder harbor betray wasp final emotion task crumble siren bottom lizard educate guess current outdoor pair theory focus wife stone';

  beforeAll(async () => {
    const rootDir = await getRootDir();

    contractDirVerifier = rootDir + `/contracts/cosmos/verifier`;
    parseDataTool = `${contractDirVerifier}/nimcache/verifier_parse_data`;
    pathToVerifyUtils =
      rootDir + `/vendor/eth2-light-client-updates/prater/capella-updates-94/`;
    updateFiles = glob(pathToVerifyUtils + `proof*.json`);

    await compileContractMain(null);

    cosmos = await setUpCosmosTestnet(mnemonic);
    DendrETHWalletInfo = cosmos.walletInfo;
  }, 360000 /* timeout in milliseconds */);

  test('Check "Verifier" after initialization', async () => {
    console.info("Running 'Check Verifier after initialization' test");
    const expectedHeaderHash =
      '76,231,107,116,120,203,14,238,74,50,199,242,91,181,97,202,29,15,68,77,23,22,200,246,242,96,144,14,244,95,55,210';
    const uploadReceipt = await uploadVerifierContract('wasm', cosmos);
    console.info(
      'Upload of `Verifier in Cosmos` succeeded. Receipt:',
      uploadReceipt,
    );
    console.info(
      'Upload of `Verifier in Cosmos` succeeded. Receipt:',
      uploadReceipt,
    );

    const defaultInitHeaderRoot = JSON.parse(
      readFileSync(replaceInTextProof(updateFiles[0])),
    ).attestedHeaderRoot;

    const defaultDomain =
      '0x07000000628941ef21d1fe8c7134720add10bb91e3b02c007e0046d2472c6695';

    const instantiation = await instantiateVerifierContract(
      uploadReceipt,
      defaultInitHeaderRoot,
      defaultDomain,
      cosmos,
    );
    cosmosContract = new CosmosContract(
      instantiation.contractAddress,
      DendrETHWalletInfo.address,
      rpcEndpoint,
      'local',
    );
    console.info('Contract instantiated at: ', instantiation.contractAddress);

    // Query contract after Instantiation
    const queryResultAfterInitialization =
      await cosmosContract.optimisticHeaderRoot();

    const headerHash = queryResultAfterInitialization
      .toString()
      .replace(/\s/g, '');
    expect(headerHash).toEqual(expectedHeaderHash);
  }, 300000);

  test('Check "Verifier" after one update', async () => {
    console.info("Running 'Check Verifier after one update' test");

    var updatePath;
    for (var proofFilePath of updateFiles.slice(1, 2)) {
      updatePath = replaceInTextProof(proofFilePath);

      // Parse the contract specific message that is passed to the contract
      const parseUpdateDataCommand = `${parseDataTool} updateDataForRelayTest \
      --proofPathRelay=${proofFilePath} --updatePathRelay=${updatePath}`;
      console.info(`Parsing data for update 1: \n ➤ ${parseUpdateDataCommand}`);
      const updateDataExec = exec(parseUpdateDataCommand);
      const updateData = (await updateDataExec).stdout.replace(/\s/g, '');
      console.info(`Parsed update data: \n  ╰─➤ ${updateData}`);
      // Execute update on the contract with the contract specific message
      await cosmosContract.postUpdateOnChain(JSON.parse(updateData));
    }

    //What is the expected result of the query below
    const getExpectedHeaderCommand = `${parseDataTool} expectedHeaderRootPath \
    --expectedHeaderRootPath=${updatePath}`;

    console.info(
      `Parsing expected new header \n  ╰─➤ ${getExpectedHeaderCommand}`,
    );
    const expectedHeaderExec = exec(getExpectedHeaderCommand);
    const expectedHeader = (await expectedHeaderExec).stdout
      .toString()
      .replace(/\s/g, '')
      .replace('[', '')
      .replace(']', '');
    console.info(`Parsed expected new header: \n  ╰─➤ [${expectedHeader}]`);
    // await sleep(10000);
    // Query contract after one update
    const headerAfterOneUpdate = await cosmosContract.optimisticHeaderRoot();

    const header = headerAfterOneUpdate.toString().replace(/\s/g, '');
    expect(header).toEqual(expectedHeader);
  }, 300000);

  test('Check "Verifier" after 5 updates', async () => {
    console.info("Running 'Check Verifier after 5 updates' test");

    const numOfUpdates = 6;
    var updatePath;
    var updateCounter = 1;
    for (var proofFilePath of updateFiles.slice(2, numOfUpdates)) {
      updatePath = replaceInTextProof(proofFilePath);

      updateCounter++;
      // Parse the contract specific message that is passed to the contract
      const parseUpdateDataCommand = `${parseDataTool} updateDataForRelayTest \
        --proofPathRelay=${proofFilePath} --updatePathRelay=${updatePath}`;
      console.info(
        `Parsing data for update ${updateCounter}: \n  ╰─➤ ${parseUpdateDataCommand}`,
      );
      const updateDataExec = exec(parseUpdateDataCommand);
      const updateData = (await updateDataExec).stdout.replace(/\s/g, '');
      console.info(`Parsed update data: \n  ╰─➤ ${updateData}`);

      // Execute update on the contract with the contract specific message
      await cosmosContract.postUpdateOnChain(JSON.parse(updateData));
    }

    // What is the expected result of the query below
    const getExpectedHeaderHashCommand = `${parseDataTool} expectedHeaderRootPath --expectedHeaderRootPath=${updatePath}`;
    console.info(
      `Parsing expected latest optimistic header hash \n   ${getExpectedHeaderHashCommand}`,
    );
    const expectedHeaderHahsExec = exec(getExpectedHeaderHashCommand);
    const expectedHeaderHash = (await expectedHeaderHahsExec).stdout
      .toString()
      .replace(/\s/g, '')
      .replace('[', '')
      .replace(']', '');
    console.info(
      `Parsed expected latest optimistic header hash: \n  ╰─➤ [${expectedHeaderHash}]`,
    );

    const headerHashAfter20Update = await cosmosContract.optimisticHeaderRoot();
    const headerHash = headerHashAfter20Update.toString().replace(/\s/g, '');
    expect(headerHash).toEqual(expectedHeaderHash);

    await stopCosmosNode();
  }, 2000000);
});
