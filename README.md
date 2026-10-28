# Leash

**On-chain spending rules for AI agents on BOT Chain.**

Leash gives an AI agent its own key on a [Kernel v3.3](https://github.com/zerodevapp/kernel) smart account, and the
account itself enforces what that key may do. No server holds the agent's limits: they are checked in ERC-4337
validation, before anything executes.

| Rule | What it does |
|---|---|
| Budgets | Per token per period, e.g. 1 BOT and 50 USDT a day. ERC-20 `transfer`, `approve`, `increaseAllowance` and `transferFrom` all count, so an agent cannot dodge a cap by approving a spender. |
| Allowlist | Only listed `(target, selector)` pairs. Everything else is refused. |
| Validity | A start time and an expiry. |
| Kill switch | The owner, or a guardian key, freezes the agent instantly. A guardian can freeze but never unfreeze. |
| Gas | Optional: the operation's maximum gas cost counts against the BOT budget. |
| Always refused | Calls to the account itself or to the policy, delegatecalls, and ERC-1271 signatures by the agent key (a signed permit would bypass the budget). |

## Why

BOT Chain's Agent Wallet is custodial and its only control is a recipient allowlist. Leash is non-custodial: the owner
keeps the root key, the agent holds a key that can only act within the rules, and the rules live on-chain.

## How it works

Leash is a Kernel *permission*: a policy (`LeashPolicy`) plus a signer (`LeashSigner`, the agent's ECDSA key).
Kernel calls the policy for every user operation the agent signs.

ERC-4337 forbids reading `block.timestamp` during validation, so a daily budget cannot ask the clock. Instead the agent
names the period it is spending in, and the policy returns that period's `[start, end]` as `validAfter`/`validUntil`.
The EntryPoint rejects the operation outside that window, so a wrong period cannot be used. All storage read during
validation is keyed by the account address innermost, as ERC-7562 requires.

Spending is recorded at validation. If the call later reverts, the budget stays spent: the rule errs on the owner's side.

## Deployed on BOT Chain mainnet (chain 677)

| Contract | Address |
|---|---|
| LeashPolicy | [`0x7036066bEe567C1f9719ee28d21fC50D857AFb9f`](https://scan.botchain.ai/address/0x7036066bEe567C1f9719ee28d21fC50D857AFb9f) |
| LeashSigner | [`0x39848370bb2cfCEC6F1268b7DAe6878fcEeCF4dd`](https://scan.botchain.ai/address/0x39848370bb2cfCEC6F1268b7DAe6878fcEeCF4dd) |
| Kernel v3.3 implementation | [`0x35345d0D46fe39739d3C7A0d347F9D0813D803Df`](https://scan.botchain.ai/address/0x35345d0D46fe39739d3C7A0d347F9D0813D803Df) |
| KernelFactory | [`0xD0595f6f50147767280d42C404e35c1EBFd09537`](https://scan.botchain.ai/address/0xD0595f6f50147767280d42C404e35c1EBFd09537) |
| ECDSAValidator (owner key) | [`0x888E8df947844bc7063B51E5b5C97b144F255be0`](https://scan.botchain.ai/address/0x888E8df947844bc7063B51E5b5C97b144F255be0) |
| EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| LeashManifest (owned index of the above) | [`0x083EF86c7606A260240C69A4A82ACdF2588D9A97`](https://scan.botchain.ai/address/0x083EF86c7606A260240C69A4A82ACdF2588D9A97) |

Deployed with CREATE2 (salt `keccak256("leash.v1")`), so the same addresses apply on any chain the script runs on.
LeashManifest is deployed directly by the project wallet and owned by it, so the project can prove control of it;
[`tally.json`](tally.json) links these contracts to this repository on [Tally](https://tallyarc.tech).

### Live run on mainnet

A leashed agent with a 0.002 BOT daily budget that may only pay its owner, through BOT's Skandha bundler:

| Step | Result |
|---|---|
| Agent pays 0.0015 BOT | ✅ [tx](https://scan.botchain.ai/tx/0xc5742e69a508e06ac2edc901a04f2b4054868b5aab0c79a6cb5dde8eb59724a2), submitted by the bundler |
| Agent tries 0.001 BOT more | 🚫 `OverBudget`, refused at simulation |
| Agent pays an unlisted address | 🚫 `CallNotAllowed` |
| Guardian freezes, agent retries | 🚫 `IsFrozen`, then the owner unfreezes ✅ |

## Repository

| Path | What it is |
|---|---|
| `src/LeashPolicy.sol` | The policy: budgets, allowlist, validity, freeze |
| `src/LeashSigner.sol` | The agent key (EIP-191 over the user operation hash) |
| `src/LeashManifest.sol` | Owned on-chain index of the official addresses |
| `test/` | 26 tests against the real EntryPoint v0.7 bytecode (fetched from BOT mainnet) and Kernel built from source |
| `script/Deploy.s.sol` | Idempotent CREATE2 deployment of the full stack |
| `client/` | TypeScript (viem): builds owner and agent user operations, talks to the bundler; `src/live.ts` is the run above |
| `deployments/677.json` | Mainnet addresses |

## Use it

```sh
git clone --recursive https://github.com/Miracle656/leash && cd leash
forge test

# deploy (PRIVATE_KEY in .env)
forge script script/Deploy.s.sol --rpc-url bot --broadcast

# end-to-end run: creates an account, leashes a fresh agent key, exercises the rules
cd client && npm install
npx tsx src/live.ts                                              # BOT mainnet via the bundler
RPC_URL=http://127.0.0.1:8545 SUBMIT=direct npx tsx src/live.ts  # against `anvil --fork-url https://rpc.botchain.ai`
```

To leash your own agent, see `installLeashCalls`, `signAsAgent` and `Bundler` in `client/src/leash.ts`.

## Status

Not audited. The tests cover each rule and its rejection path, and the mainnet run confirms BOT's bundler accepts the
policy's validation. Treat budgets as a safety net, not a guarantee, until it has had an independent review.

MIT licensed.
