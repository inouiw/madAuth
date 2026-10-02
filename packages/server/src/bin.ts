#!/usr/bin/env node
import { runCli } from './cli.js';

const { output, exitCode } = await runCli(process.argv.slice(2));
(exitCode ? console.error : console.log)(output);
process.exitCode = exitCode;
