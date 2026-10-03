#!/usr/bin/env node
import { runCli } from './cli.js';

const { output, exitCode } = await runCli(process.argv.slice(2));
// `start` prints nothing here, and its server keeps the process running.
if (output) (exitCode ? console.error : console.log)(output);
process.exitCode = exitCode;
