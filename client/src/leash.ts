// Leash client: builds Kernel v3.3 user operations for an owner and for a leashed agent.
import {
  concat,
  encodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  pad,
  parseAbi,
  toHex,
  type Address,
  type Hex,
  type LocalAccount,
  type PublicClient,
} from "viem";
import { getUserOperationHash, toPackedUserOperation, type UserOperation } from "viem/account-abstraction";

export const ENTRYPOINT: Address = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
export const NATIVE: Address = "0x0000000000000000000000000000000000000000";

export const kernelAbi = parseAbi([
  "function initialize(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)",
  "function execute(bytes32 mode, bytes executionCalldata) payable",
  "function installValidations(bytes21[] vIds, (uint32 nonce, address hook)[] configs, bytes[] validationData, bytes[] hookData) payable",
  "function grantAccess(bytes21 vId, bytes4 selector, bool allow) payable",
  "function currentNonce() view returns (uint32)",
  "function validationConfig(bytes21 vId) view returns ((uint32 nonce, address hook))",
]);

export const factoryAbi = parseAbi([
  "function createAccount(bytes data, bytes32 salt) payable returns (address)",
  "function getAddress(bytes data, bytes32 salt) view returns (address)",
]);

export const entryPointAbi = parseAbi([
  "struct PackedUserOperation { address sender; uint256 nonce; bytes initCode; bytes callData; bytes32 accountGasLimits; uint256 preVerificationGas; bytes32 gasFees; bytes paymasterAndData; bytes signature; }",
  "function handleOps(PackedUserOperation[] ops, address beneficiary)",
  "function getNonce(address sender, uint192 key) view returns (uint256)",
  "function balanceOf(address account) view returns (uint256)",
  "error FailedOp(uint256 opIndex, string reason)",
  "error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner)",
  "event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)",
]);

export const policyAbi = parseAbi([
  "struct Config { uint48 validAfter; uint48 validUntil; uint48 periodStart; uint32 periodLength; uint32 generation; bool installed; bool frozen; bool countGas; address guardian; }",
  "function configOf(address account, bytes32 id) view returns (Config)",
  "function spentOf(address account, bytes32 id, address token, uint256 period) view returns (uint256)",
  "function limitOf(address account, bytes32 id, address token) view returns (bool set, uint256 limit)",
  "function periodAt(address account, bytes32 id, uint256 timestamp) view returns (uint256)",
  "function setFrozen(bytes32 id, bool frozen)",
  "function freeze(address account, bytes32 id)",
]);

export interface Budget {
  token: Address; // NATIVE = BOT
  limit: bigint; // per period, smallest units
}

export interface CallRule {
  target: Address;
  selector: Hex; // 0x00000000 = plain value transfer
}

export interface LeashConfig {
  validAfter: number;
  validUntil: number; // 0 = never
  periodStart: number;
  periodLength: number; // seconds, 0 = lifetime budget
  countGas: boolean;
  guardian: Address;
  budgets: Budget[];
  calls: CallRule[];
}

export interface Deployment {
  chainId: number;
  kernelFactory: Address;
  ecdsaValidator: Address;
  leashPolicy: Address;
  leashSigner: Address;
}

// --------------------------------------------------------------- identifiers

/** Kernel validation id of a plain validator: 0x01 ++ address. */
export const validatorId = (validator: Address): Hex => concat(["0x01", validator]);

/** Kernel validation id of a permission: 0x02 ++ 4-byte id, right-padded to 21 bytes. */
export const permissionVId = (permissionId: Hex): Hex => pad(concat(["0x02", permissionId]), { size: 21, dir: "right" });

/** The bytes32 id Kernel hands to the policy and signer. */
export const permissionKey = (permissionId: Hex): Hex => pad(permissionId, { size: 32, dir: "right" });

/** EntryPoint nonce key for a permission: [mode 0x00][type 0x02][id, 20 bytes][parallel key 0]. */
export const permissionNonceKey = (permissionId: Hex): bigint =>
  BigInt(concat(["0x00", "0x02", pad(permissionId, { size: 20, dir: "right" }), "0x0000"]));

// ------------------------------------------------------------- call encoding

export const kernelInitData = (ecdsaValidator: Address, owner: Address): Hex =>
  encodeFunctionData({
    abi: kernelAbi,
    functionName: "initialize",
    args: [validatorId(ecdsaValidator), NATIVE, owner, "0x", []],
  });

export const executeSingle = (target: Address, value: bigint, data: Hex = "0x"): Hex =>
  encodeFunctionData({
    abi: kernelAbi,
    functionName: "execute",
    args: [pad("0x00", { size: 32 }), encodePacked(["address", "uint256", "bytes"], [target, value, data])],
  });

const leashConfigType = [
  {
    type: "tuple",
    components: [
      { name: "validAfter", type: "uint48" },
      { name: "validUntil", type: "uint48" },
      { name: "periodStart", type: "uint48" },
      { name: "periodLength", type: "uint32" },
      { name: "countGas", type: "bool" },
      { name: "guardian", type: "address" },
      {
        name: "budgets",
        type: "tuple[]",
        components: [
          { name: "token", type: "address" },
          { name: "limit", type: "uint256" },
        ],
      },
      {
        name: "calls",
        type: "tuple[]",
        components: [
          { name: "target", type: "address" },
          { name: "selector", type: "bytes4" },
        ],
      },
    ],
  },
] as const;

/** Kernel permission install data: [policy, signer], each as flag(2) ++ module(20) ++ init data. */
export function permissionData(d: Deployment, agent: Address, cfg: LeashConfig): Hex {
  const policyInit = encodeAbiParameters(leashConfigType, [cfg]);
  const entries: Hex[] = [
    concat(["0x0000", d.leashPolicy, policyInit]),
    concat(["0x0000", d.leashSigner, agent]),
  ];
  return encodeAbiParameters([{ type: "bytes[]" }], [entries]);
}

export function installLeashCalls(d: Deployment, agent: Address, cfg: LeashConfig, permissionId: Hex, nonce: number) {
  const vId = permissionVId(permissionId);
  return {
    install: encodeFunctionData({
      abi: kernelAbi,
      functionName: "installValidations",
      args: [[vId], [{ nonce, hook: "0x0000000000000000000000000000000000000001" }], [permissionData(d, agent, cfg)], ["0x"]],
    }),
    grant: encodeFunctionData({
      abi: kernelAbi,
      functionName: "grantAccess",
      args: [vId, "0xe9ae5c53", true], // Kernel.execute
    }),
  };
}

// ----------------------------------------------------------- user operations

export interface GasSettings {
  verificationGasLimit: bigint;
  callGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

export function newUserOp(sender: Address, nonce: bigint, callData: Hex, gas: GasSettings): UserOperation<"0.7"> {
  return { sender, nonce, callData, signature: "0x", ...gas };
}

export const userOpHash = (op: UserOperation<"0.7">, chainId: number): Hex =>
  getUserOperationHash({ userOperation: op, entryPointAddress: ENTRYPOINT, entryPointVersion: "0.7", chainId });

/** Root (owner) signature: an EIP-191 signature over the user operation hash. */
export async function signAsOwner(op: UserOperation<"0.7">, owner: LocalAccount, chainId: number): Promise<Hex> {
  return owner.signMessage({ message: { raw: userOpHash(op, chainId) } });
}

/** Permission signature: [policy 0][uint64 32][period] ++ 0xff ++ agent's EIP-191 signature. */
export async function signAsAgent(
  op: UserOperation<"0.7">,
  agent: LocalAccount,
  chainId: number,
  period: bigint,
): Promise<Hex> {
  const sig = await agent.signMessage({ message: { raw: userOpHash(op, chainId) } });
  return concat(["0x00", toHex(32n, { size: 8 }), toHex(period, { size: 32 }), "0xff", sig]);
}

export const packForHandleOps = (op: UserOperation<"0.7">) => toPackedUserOperation(op);

// ------------------------------------------------------------------- bundler

export class Bundler {
  constructor(readonly url: string) {}

  async call<T>(method: string, params: unknown[]): Promise<T> {
    const res = await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }, (_, v) => (typeof v === "bigint" ? toHex(v) : v)),
    });
    const body = (await res.json()) as { result?: T; error?: { message: string; data?: unknown } };
    if (body.error) throw new BundlerError(body.error.message, body.error.data);
    return body.result as T;
  }

  estimate(op: UserOperation<"0.7">) {
    return this.call<{ preVerificationGas: Hex; verificationGasLimit: Hex; callGasLimit: Hex }>(
      "eth_estimateUserOperationGas",
      [op, ENTRYPOINT],
    );
  }

  send(op: UserOperation<"0.7">) {
    return this.call<Hex>("eth_sendUserOperation", [op, ENTRYPOINT]);
  }

  async waitForReceipt(hash: Hex, timeoutMs = 120_000) {
    const until = Date.now() + timeoutMs;
    while (Date.now() < until) {
      const r = await this.call<{ success: boolean; actualGasCost: Hex; receipt: { transactionHash: Hex } } | null>(
        "eth_getUserOperationReceipt",
        [hash],
      );
      if (r) return r;
      await new Promise((ok) => setTimeout(ok, 2000));
    }
    throw new Error(`user operation ${hash} not mined within ${timeoutMs / 1000}s`);
  }
}

export class BundlerError extends Error {
  constructor(
    message: string,
    readonly data?: unknown,
  ) {
    super(message);
  }
}

/** The current period index the agent must sign for. */
export async function currentPeriod(client: PublicClient, d: Deployment, account: Address, permissionId: Hex) {
  const block = await client.getBlock();
  return client.readContract({
    address: d.leashPolicy,
    abi: policyAbi,
    functionName: "periodAt",
    args: [account, permissionKey(permissionId), block.timestamp],
  });
}
