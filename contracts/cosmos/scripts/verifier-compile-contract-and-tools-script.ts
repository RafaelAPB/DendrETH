import yargs from 'yargs/yargs';
import { compileContractMain } from '../verifier/lib/typescript/verifier-compile-contract-and-tools';

const argv = yargs(process.argv.slice(2))
  .options({
    run: { type: 'boolean', default: false, demandOption: true },
    patch: { type: 'string', default: null, demandOption: false },
  })
  .parseSync();

if (argv.run || argv._[0] == 'run') {
  compileContractMain(argv.patch);
}
