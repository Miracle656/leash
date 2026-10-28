// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {Kernel} from "kernel/Kernel.sol";
import {KernelFactory} from "kernel/factory/KernelFactory.sol";
import {ECDSAValidator} from "kernel/validator/ECDSAValidator.sol";
import {IEntryPoint} from "kernel/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "kernel/interfaces/PackedUserOperation.sol";
import {IHook, IValidator} from "kernel/interfaces/IERC7579Modules.sol";
import {ValidatorLib} from "kernel/utils/ValidationTypeLib.sol";
import {ValidationId, PermissionId, ExecMode} from "kernel/types/Types.sol";
import {ValidationManager} from "kernel/core/ValidationManager.sol";
import {Execution} from "kernel/types/Structs.sol";
import {ERC20} from "solady/tokens/ERC20.sol";

import {LeashPolicy} from "../src/LeashPolicy.sol";
import {LeashSigner} from "../src/LeashSigner.sol";

contract TestToken is ERC20 {
    function name() public pure override returns (string memory) {
        return "Test USD";
    }

    function symbol() public pure override returns (string memory) {
        return "TUSD";
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @notice Stands in for a service an agent pays, or a router that pulls tokens.
contract Service {
    uint256 public pings;

    function ping() external payable {
        ++pings;
    }

    function pull(ERC20 token, address from, uint256 amount) external {
        token.transferFrom(from, address(this), amount);
    }
}

/// @dev Real EntryPoint v0.7 bytecode (fetched from BOT Chain mainnet) and Kernel v3.3
///      built from source, so every test goes through the production validation path.
abstract contract LeashBase is Test {
    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant SENDER_CREATOR = 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C;
    bytes4 constant PERMISSION_ID = 0x1ea5e001;

    IEntryPoint entryPoint = IEntryPoint(ENTRYPOINT);
    Kernel kernel;
    LeashPolicy policy;
    LeashSigner signer;
    TestToken token;
    Service service;

    address owner;
    uint256 ownerKey;
    address agent;
    uint256 agentKey;
    address guardian = makeAddr("guardian");
    address payable beneficiary = payable(makeAddr("beneficiary"));
    address shop = makeAddr("shop");

    function setUp() public virtual {
        vm.etch(ENTRYPOINT, vm.parseBytes(vm.trim(vm.readFile("test/fixtures/entrypoint07.hex"))));
        vm.etch(SENDER_CREATOR, vm.parseBytes(vm.trim(vm.readFile("test/fixtures/sendercreator07.hex"))));
        vm.warp(1_800_000_000);

        (owner, ownerKey) = makeAddrAndKey("owner");
        (agent, agentKey) = makeAddrAndKey("agent");

        Kernel impl = new Kernel(entryPoint);
        KernelFactory factory = new KernelFactory(address(impl));
        ECDSAValidator ownerValidator = new ECDSAValidator();
        policy = new LeashPolicy();
        signer = new LeashSigner();
        token = new TestToken();
        service = new Service();

        bytes memory init = abi.encodeCall(
            Kernel.initialize,
            (
                ValidatorLib.validatorToIdentifier(IValidator(address(ownerValidator))),
                IHook(address(0)),
                abi.encodePacked(owner),
                hex"",
                new bytes[](0)
            )
        );
        kernel = Kernel(payable(factory.createAccount(init, bytes32(0))));
        vm.deal(address(kernel), 100 ether);
        token.mint(address(kernel), 1_000e6);
    }

    // ------------------------------------------------------------ config helpers

    function defaultConfig() internal view returns (LeashPolicy.InstallConfig memory cfg) {
        cfg.periodStart = uint48(block.timestamp);
        cfg.periodLength = 1 days;
        cfg.guardian = guardian;
        cfg.budgets = new LeashPolicy.Budget[](2);
        cfg.budgets[0] = LeashPolicy.Budget(address(0), 1 ether);
        cfg.budgets[1] = LeashPolicy.Budget(address(token), 50e6);
        cfg.calls = new LeashPolicy.CallRule[](2);
        cfg.calls[0] = LeashPolicy.CallRule(address(service), Service.ping.selector);
        cfg.calls[1] = LeashPolicy.CallRule(shop, bytes4(0));
    }

    function vId() internal pure returns (ValidationId) {
        return ValidatorLib.permissionToIdentifier(PermissionId.wrap(PERMISSION_ID));
    }

    function permissionId() internal pure returns (bytes32) {
        return bytes32(PERMISSION_ID);
    }

    function permissionData(LeashPolicy.InstallConfig memory cfg) internal view returns (bytes memory) {
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodePacked(bytes2(0), address(policy), abi.encode(cfg));
        data[1] = abi.encodePacked(bytes2(0), address(signer), agent);
        return abi.encode(data);
    }

    function installLeash(LeashPolicy.InstallConfig memory cfg) internal {
        ValidationId[] memory ids = new ValidationId[](1);
        ids[0] = vId();
        ValidationManager.ValidationConfig[] memory configs = new ValidationManager.ValidationConfig[](1);
        // Kernel bumps its nonce when the id was already used at the current nonce.
        uint32 nonce = kernel.currentNonce();
        if (kernel.validationConfig(vId()).nonce == nonce) ++nonce;
        configs[0] = ValidationManager.ValidationConfig(nonce, IHook(address(1)));
        bytes[] memory vData = new bytes[](1);
        vData[0] = permissionData(cfg);
        bytes[] memory hookData = new bytes[](1);

        _ownerOp(abi.encodeCall(Kernel.installValidations, (ids, configs, vData, hookData)));
        _ownerOp(abi.encodeCall(Kernel.grantAccess, (vId(), Kernel.execute.selector, true)));
    }

    // ------------------------------------------------------------ call encoding

    function single(address target, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeCall(Kernel.execute, (ExecMode.wrap(bytes32(0)), abi.encodePacked(target, value, data)));
    }

    function batch(Execution[] memory calls) internal pure returns (bytes memory) {
        return abi.encodeCall(Kernel.execute, (ExecMode.wrap(bytes32(uint256(1) << 248)), abi.encode(calls)));
    }

    function ownerCall(address target, bytes memory data) internal {
        _ownerOp(single(target, 0, data));
    }

    // ------------------------------------------------------------ user operations

    function _baseOp(uint256 nonce, bytes memory callData) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(kernel),
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1_000_000), uint128(1_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _sign(uint256 key, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(key, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)));
        return abi.encodePacked(r, s, v);
    }

    function _ownerOp(bytes memory callData) internal {
        PackedUserOperation memory op = _baseOp(entryPoint.getNonce(address(kernel), 0), callData);
        op.signature = _sign(ownerKey, entryPoint.getUserOpHash(op));
        _submit(op);
    }

    function agentOp(bytes memory callData, uint256 period) internal view returns (PackedUserOperation memory op) {
        return agentOpSigned(callData, period, agentKey);
    }

    function agentOpSigned(bytes memory callData, uint256 period, uint256 key)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        uint192 nonceKey = ValidatorLib.encodeAsNonceKey(0x00, 0x02, bytes20(PERMISSION_ID), 0);
        op = _baseOp(entryPoint.getNonce(address(kernel), nonceKey), callData);
        _signAgent(op, period, key);
    }

    /// @dev Kernel permission signature: [policy idx 0][uint64 len][period] then 0xff + signer sig.
    function _signAgent(PackedUserOperation memory op, uint256 period, uint256 key) internal view {
        bytes memory sig = _sign(key, entryPoint.getUserOpHash(op));
        op.signature = abi.encodePacked(uint8(0), uint64(32), bytes32(period), hex"ff", sig);
    }

    function _submit(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.recordLogs();
        entryPoint.handleOps(ops, beneficiary);
        // A failed execution does not revert handleOps, so check the event.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == topic && logs[i].emitter == ENTRYPOINT) {
                (, bool success,,) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
                assertTrue(success, "user operation execution failed");
            }
        }
    }

    function runAgent(bytes memory callData, uint256 period) internal {
        _submit(agentOp(callData, period));
    }

    /// @dev A policy revert surfaces from the EntryPoint as AA23 with the inner error.
    function expectPolicyRevert(bytes memory inner) internal {
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", inner));
    }

    function expectOutOfWindow() internal {
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due"));
    }

    function expectBadSignature() internal {
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
    }
}
