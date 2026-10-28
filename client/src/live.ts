// End-to-end run of Leash: owner creates a Kernel account and leashes an agent key,
// then the agent transacts through the bundler and the policy's limits are exercised.
//
//   RPC_URL=http://127.0.0.1:8545 SUBMIT=direct npx tsx src/live.ts   # dry run on an anvil fork
//   npx tsx src/live.ts                                               # BOT mainnet, via the bundler
import { readFileSync, appendFileSync } from "node:fs";
import { config as loadEnv } from "dotenv";
import {
  createPublicClient,
  createWalletClient,
  decodeErrorResult,
  defineChain,
  encodeFunctionData,
  formatEther,
  http,
  parseAbi,
  parseEther,
  parseEventLogs,
  type Address,
  type Hex,
  type TransactionReceipt,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { UserOperation } from "viem/account-abstraction";
import {
  Bundler,
  BundlerError,
  ENTRYPOINT,
  NATIVE,
  currentPeriod,
  entryPointAbi,
  executeSingle,
  factoryAbi,
  installLeashCalls,
  kernelAbi,
  kernelInitData,
  newUserOp,
  packForHandleOps,
  permissionKey,
  permissionNonceKey,
  permissionVId,
  policyAbi,
  signAsAgent,
  signAsOwner,
  type Deployment,
  type GasSettings,
  type LeashConfig,
} from "./leash.js";

const ENV_PATH = "../.env";
loadEnv({ path: ENV_PATH });
if (!process.env.AGENT_PRIVATE_KEY) {
  // A fresh agent key, written next to the owner key and never printed.
  appendFileSync(ENV_PATH, `AGENT_PRIVATE_KEY=${generatePrivateKey()}\n`);
  loadEnv({ path: ENV_PATH, override: true });
}

const RPC_URL = process.env.RPC_URL ?? "https://rpc.botchain.ai";
const BUNDLER_URL = process.env.BUNDLER_URL ?? "https://bundler.botchain.ai/rpc";
const DIRECT = process.env.SUBMIT === "direct";
const PERMISSION_ID: Hex = "0x1ea5e001";
const SALT: Hex = "0x0000000000000000000000000000000000000000000000000000000000000000";

const deployment: Deployment = JSON.parse(readFileSync("../deployments/677.json", "utf8"));
const bot = defineChain({
  id: 677,
  name: "BOT Chain",
  nativeCurrency: { name: "BOT", symbol: "BOT", decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
  blockExplorers: { default: { name: "BOTScan", url: "https://scan.botchain.ai" } },
});

const owner = privateKeyToAccount(process.env.PRIVATE_KEY as Hex);
const agent = privateKeyToAccount(process.env.AGENT_PRIVATE_KEY as Hex);
const client = createPublicClient({ chain: bot, transport: http() });
const wallet = createWalletClient({ chain: bot, transport: http(), account: owner });
const bundler = new Bundler(BUNDLER_URL);

const leashErrors = parseAbi([
  "error NotInstalled()",
  "error IsFrozen()",
  "error BadPeriod()",
  "error UnsupportedCall()",
  "error SelfCall(address target)",
  "error CallNotAllowed(address target, bytes4 selector)",
  "error NoBudget(address token)",
  "error OverBudget(address token, uint256 period, uint256 total, uint256 limit)",
]);

// ------------------------------------------------------------------ ledger

const ledger: { step: string; tx: Hex; cost: bigint }[] = [];

async function record(step: string, receipt: TransactionReceipt) {
  if (receipt.status !== "success") throw new Error(`${step}: transaction ${receipt.transactionHash} reverted`);
  const cost = receipt.gasUsed * receipt.effectiveGasPrice;
  ledger.push({ step, tx: receipt.transactionHash, cost });
  console.log(`   tx ${receipt.transactionHash}  gas ${receipt.gasUsed}  cost ${formatEther(cost)} BOT`);
}

async function sendTx(step: string, tx: Promise<Hex>) {
  const hash = await tx;
  await record(step, await client.waitForTransactionReceipt({ hash }));
}

// ----------------------------------------------------------- owner (root) ops

/** Owner operations go straight to the EntryPoint; the owner EOA pays the gas. */
async function ownerOps(step: string, account: Address, calls: Hex[]) {
  const fees = { maxFeePerGas: 1n, maxPriorityFeePerGas: 1n }; // owner reimburses itself; keep it at cost
  const gas = { verificationGasLimit: 300_000n, callGasLimit: 700_000n, preVerificationGas: 60_000n, ...fees };
  const first = await client.readContract({ address: ENTRYPOINT, abi: entryPointAbi, functionName: "getNonce", args: [account, 0n] });
  const ops = [];
  for (let i = 0; i < calls.length; i++) {
    const op = newUserOp(account, first + BigInt(i), calls[i], gas);
    op.signature = await signAsOwner(op, owner, bot.id);
    ops.push(packForHandleOps(op));
  }
  const hash = await wallet.writeContract({ address: ENTRYPOINT, abi: entryPointAbi, functionName: "handleOps", args: [ops, owner.address] });
  const receipt = await client.waitForTransactionReceipt({ hash });
  const events = parseEventLogs({ abi: entryPointAbi, logs: receipt.logs, eventName: "UserOperationEvent" });
  if (events.length !== calls.length || events.some((e) => !e.args.success)) {
    throw new Error(`${step}: a user operation failed in execution (${hash})`);
  }
  await record(step, receipt);
}

// ------------------------------------------------------------------ agent ops

type Outcome = { ok: true; userOpHash: Hex; tx: Hex; cost: bigint } | { ok: false; reason: string };

async function agentOp(callData: Hex): Promise<Outcome> {
  const account = await accountAddress();
  const nonce = await client.readContract({
    address: ENTRYPOINT,
    abi: entryPointAbi,
    functionName: "getNonce",
    args: [account, permissionNonceKey(PERMISSION_ID)],
  });
  const period = await currentPeriod(client, deployment, account, PERMISSION_ID);
  const fees = DIRECT
    ? { maxFeePerGas: 20_000_000_000n, maxPriorityFeePerGas: 20_000_000_000n }
    : await bundler.call<{ maxFeePerGas: Hex; maxPriorityFeePerGas: Hex }>("skandha_getGasPrice", []).then((f) => ({
        maxFeePerGas: BigInt(f.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(f.maxPriorityFeePerGas),
      }));
  let gas: GasSettings = { verificationGasLimit: 250_000n, callGasLimit: 100_000n, preVerificationGas: 60_000n, ...fees };
  const op: UserOperation<"0.7"> = newUserOp(account, nonce, callData, gas);
  op.signature = await signAsAgent(op, agent, bot.id, period);

  try {
    if (DIRECT) return await agentDirect(op);
    const est = await bundler.estimate(op);
    gas = {
      ...gas,
      verificationGasLimit: (BigInt(est.verificationGasLimit) * 13n) / 10n,
      callGasLimit: (BigInt(est.callGasLimit) * 13n) / 10n,
      preVerificationGas: (BigInt(est.preVerificationGas) * 11n) / 10n,
    };
    Object.assign(op, gas);
    op.signature = await signAsAgent(op, agent, bot.id, period);
    const userOpHash = await bundler.send(op);
    const r = await bundler.waitForReceipt(userOpHash);
    if (!r.success) return { ok: false, reason: `executed but reverted (${r.receipt.transactionHash})` };
    return { ok: true, userOpHash, tx: r.receipt.transactionHash, cost: BigInt(r.actualGasCost) };
  } catch (e) {
    return { ok: false, reason: explain(e) };
  }
}

/** Fork dry runs have no bundler: submit the same operation to the EntryPoint. */
async function agentDirect(op: UserOperation<"0.7">): Promise<Outcome> {
  try {
    const hash = await wallet.writeContract({
      address: ENTRYPOINT,
      abi: entryPointAbi,
      functionName: "handleOps",
      args: [[packForHandleOps(op)], owner.address],
    });
    const receipt = await client.waitForTransactionReceipt({ hash });
    const [ev] = parseEventLogs({ abi: entryPointAbi, logs: receipt.logs, eventName: "UserOperationEvent" });
    if (!ev?.args.success) return { ok: false, reason: "executed but reverted" };
    return { ok: true, userOpHash: ev.args.userOpHash, tx: hash, cost: ev.args.actualGasCost };
  } catch (e) {
    return { ok: false, reason: explain(e) };
  }
}

/** Pull a Leash error name out of a bundler or node error, wherever it is nested. */
function explain(e: unknown): string {
  const text = e instanceof BundlerError ? `${e.message} ${JSON.stringify(e.data ?? "")}` : String((e as Error)?.message ?? e);
  for (const m of text.matchAll(/0x[0-9a-fA-F]{8,}/g)) {
    const hex = m[0];
    for (let i = 0; i + 8 <= hex.length - 2; i += 2) {
      try {
        const d = decodeErrorResult({ abi: leashErrors, data: `0x${hex.slice(2 + i)}` as Hex });
        return `${d.errorName}(${(d.args ?? []).map(String).join(", ")})`;
      } catch {}
    }
  }
  return text.slice(0, 300);
}

// ------------------------------------------------------------------- steps

let _account: Address | undefined;
async function accountAddress(): Promise<Address> {
  _account ??= await client.readContract({
    address: deployment.kernelFactory,
    abi: factoryAbi,
    functionName: "getAddress",
    args: [kernelInitData(deployment.ecdsaValidator, owner.address), SALT],
  });
  return _account;
}

function expectBlocked(name: string, out: Outcome, want: string) {
  if (out.ok) throw new Error(`${name}: expected a rejection, but it went through (${out.tx})`);
  if (!out.reason.startsWith(want)) throw new Error(`${name}: rejected for the wrong reason: ${out.reason}`);
  console.log(`   rejected as expected: ${out.reason}  (no gas spent)`);
}

async function main() {
  console.log(`network ${RPC_URL}  submit ${DIRECT ? "direct to EntryPoint" : `bundler ${BUNDLER_URL}`}`);
  console.log(`owner   ${owner.address}`);
  console.log(`agent   ${agent.address}`);
  const startBalance = await client.getBalance({ address: owner.address });
  const account = await accountAddress();
  console.log(`account ${account}\n`);

  console.log("1. create the Kernel account");
  if ((await client.getCode({ address: account })) === undefined) {
    await sendTx(
      "create account",
      wallet.writeContract({
        address: deployment.kernelFactory,
        abi: factoryAbi,
        functionName: "createAccount",
        args: [kernelInitData(deployment.ecdsaValidator, owner.address), SALT],
      }),
    );
  } else console.log("   already exists");

  console.log("2. fund it");
  if ((await client.getBalance({ address: account })) < parseEther("0.008")) {
    await sendTx("fund account", wallet.sendTransaction({ to: account, value: parseEther("0.012") }));
  } else console.log("   already funded");

  console.log("3. leash the agent: 0.002 BOT a day, may only pay the owner, guardian = owner");
  const id = permissionKey(PERMISSION_ID);
  const cfgNow = await client.readContract({ address: deployment.leashPolicy, abi: policyAbi, functionName: "configOf", args: [account, id] });
  if (!cfgNow.installed) {
    const now = Number((await client.getBlock()).timestamp);
    const day = 86_400;
    const cfg: LeashConfig = {
      validAfter: 0,
      validUntil: now + 30 * day,
      periodStart: Math.floor(now / day) * day,
      periodLength: day,
      countGas: false,
      guardian: owner.address,
      budgets: [{ token: NATIVE, limit: parseEther("0.002") }],
      calls: [{ target: owner.address, selector: "0x00000000" }],
    };
    let nonce = await client.readContract({ address: account, abi: kernelAbi, functionName: "currentNonce" });
    const existing = await client.readContract({ address: account, abi: kernelAbi, functionName: "validationConfig", args: [permissionVId(PERMISSION_ID)] });
    if (existing.nonce === nonce) nonce += 1;
    const { install, grant } = installLeashCalls(deployment, agent.address, cfg, PERMISSION_ID, nonce);
    await ownerOps("install leash", account, [install, grant]);
  } else console.log("   already leashed");

  console.log("4. agent pays the owner 0.0015 BOT (within budget)");
  const pay = await agentOp(executeSingle(owner.address, parseEther("0.0015")));
  if (!pay.ok) throw new Error(`payment failed: ${pay.reason}`);
  ledger.push({ step: "agent payment (paid by account)", tx: pay.tx, cost: pay.cost });
  console.log(`   user op ${pay.userOpHash}\n   tx ${pay.tx}  cost ${formatEther(pay.cost)} BOT (from the account)`);

  console.log("5. agent tries 0.001 BOT more (over the 0.002 daily budget)");
  expectBlocked("over budget", await agentOp(executeSingle(owner.address, parseEther("0.001"))), "OverBudget");

  console.log("6. agent tries to pay an address that is not allowlisted");
  const stranger: Address = "0x000000000000000000000000000000000000dEaD";
  expectBlocked("stranger", await agentOp(executeSingle(stranger, 1n)), "CallNotAllowed");

  console.log("7. guardian freezes the agent");
  await sendTx("guardian freeze", wallet.writeContract({ address: deployment.leashPolicy, abi: policyAbi, functionName: "freeze", args: [account, id] }));
  expectBlocked("frozen", await agentOp(executeSingle(owner.address, 1n)), "IsFrozen");

  console.log("8. owner unfreezes");
  const unfreeze = executeSingle(
    deployment.leashPolicy,
    0n,
    encodeFunctionData({ abi: policyAbi, functionName: "setFrozen", args: [id, false] }),
  );
  await ownerOps("owner unfreeze", account, [unfreeze]);

  const period = await currentPeriod(client, deployment, account, PERMISSION_ID);
  const spent = await client.readContract({ address: deployment.leashPolicy, abi: policyAbi, functionName: "spentOf", args: [account, id, NATIVE, period] });
  const endBalance = await client.getBalance({ address: owner.address });
  console.log(`\nspent today by the agent: ${formatEther(spent)} of 0.002 BOT`);
  console.log("\nledger (gas):");
  for (const l of ledger) console.log(`  ${l.step.padEnd(34)} ${formatEther(l.cost).padStart(12)} BOT  ${l.tx}`);
  const total = ledger.reduce((s, l) => s + l.cost, 0n);
  console.log(`  ${"total gas".padEnd(34)} ${formatEther(total).padStart(12)} BOT`);
  console.log(`owner EOA balance ${formatEther(startBalance)} -> ${formatEther(endBalance)} BOT`);
  console.log(`account balance ${formatEther(await client.getBalance({ address: account }))} BOT, EntryPoint deposit ${formatEther(await client.readContract({ address: ENTRYPOINT, abi: entryPointAbi, functionName: "balanceOf", args: [account] }))} BOT`);
}

main().catch((e) => {
  console.error(`\nFAILED: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
