// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PolicyBase} from "kernel/sdk/moduleBase/PolicyBase.sol";
import {PackedUserOperation} from "kernel/interfaces/PackedUserOperation.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

/// @title  LeashPolicy
/// @notice On-chain spending rules for AI agent keys on a Kernel v3 smart account.
///
/// @dev    The account owner installs a Kernel *permission* made of this policy and a
///         signer (the agent's key). Every user operation the agent signs is checked
///         here, during validation, before anything executes:
///
///           - budgets:  per token (BOT = address(0)) per period, e.g. 50 USDT a day.
///                       ERC-20 `transfer`, `approve`, `increaseAllowance` and
///                       `transferFrom` on a budgeted token count against it, so an
///                       agent cannot dodge a cap by approving a spender.
///           - calls:    only allowlisted (target, selector) pairs. Default deny.
///           - validity: a start and an expiry time.
///           - freeze:   the owner, or a guardian key, can stop the agent instantly.
///           - gas:      optionally, the operation's maximum gas cost counts against
///                       the BOT budget, so an agent cannot burn funds on gas.
///
///         Calls to the account itself or to this policy are always refused, as are
///         delegatecalls and ERC-1271 signatures (an agent key must not sign permits).
///
///         ERC-4337 bans TIMESTAMP during validation, so periods are not read from the
///         clock. The agent names the period it is spending in (the policy's slot of
///         the user operation signature, a uint256; empty means period 0) and the policy
///         returns that period's [start, end] as validAfter / validUntil. The EntryPoint
///         rejects the operation outside that window, so a wrong period cannot be used.
///
///         All storage read during validation is keyed by the account address as the
///         innermost mapping key, as ERC-7562 requires for associated storage.
///
///         Spending is recorded at validation. If the call later reverts, the budget
///         stays spent: the rule errs on the side of the owner.
contract LeashPolicy is PolicyBase {
    // ------------------------------------------------------------------ types

    struct Budget {
        address token; // address(0) = native BOT
        uint256 limit; // per period
    }

    struct CallRule {
        address target; // ANY_TARGET = any address
        bytes4 selector; // bytes4(0) = plain value transfer (empty calldata)
    }

    struct InstallConfig {
        uint48 validAfter; // 0 = no start time
        uint48 validUntil; // 0 = never expires
        uint48 periodStart; // anchor of period 0
        uint32 periodLength; // seconds; 0 = one lifetime budget
        bool countGas;
        address guardian; // may freeze; address(0) = none
        Budget[] budgets;
        CallRule[] calls;
    }

    struct Config {
        uint48 validAfter;
        uint48 validUntil;
        uint48 periodStart;
        uint32 periodLength;
        uint32 generation; // bumped on uninstall, so a reinstall starts clean
        bool installed;
        bool frozen;
        bool countGas;
        address guardian;
    }

    struct Limit {
        bool set;
        uint248 amount;
    }

    // ------------------------------------------------------------- constants

    address public constant NATIVE = address(0);
    address public constant ANY_TARGET = address(type(uint160).max);

    bytes4 private constant EXECUTE = 0xe9ae5c53; // execute(bytes32,bytes)
    bytes4 private constant EXECUTE_USEROP = 0x8dd7712f; // executeUserOp(PackedUserOperation,bytes32)
    bytes4 private constant TRANSFER = 0xa9059cbb;
    bytes4 private constant APPROVE = 0x095ea7b3;
    bytes4 private constant INCREASE_ALLOWANCE = 0x39509351;
    bytes4 private constant TRANSFER_FROM = 0x23b872dd;

    bytes1 private constant CALLTYPE_SINGLE = 0x00;
    bytes1 private constant CALLTYPE_BATCH = 0x01;
    bytes1 private constant EXECTYPE_DEFAULT = 0x00;
    bytes1 private constant EXECTYPE_TRY = 0x01;

    uint256 private constant MAX_PERIOD = type(uint32).max;

    // --------------------------------------------------------------- storage

    mapping(bytes32 id => mapping(address account => Config)) private _configs;

    mapping(
        uint256 gen
            => mapping(
            bytes32 id => mapping(address target => mapping(bytes4 selector => mapping(address account => bool)))
        )
    ) private _allowed;

    mapping(uint256 gen => mapping(bytes32 id => mapping(address token => mapping(address account => Limit)))) private
        _limits;

    mapping(
        uint256 gen
            => mapping(
            bytes32 id => mapping(address token => mapping(uint256 period => mapping(address account => uint256)))
        )
    ) private _spent;

    mapping(address account => uint256) private _installedCount;

    // ---------------------------------------------------------------- events

    event LeashInstalled(address indexed account, bytes32 indexed id, address guardian);
    event LeashRemoved(address indexed account, bytes32 indexed id);
    event Frozen(address indexed account, bytes32 indexed id, address by, bool frozen);
    event LimitSet(address indexed account, bytes32 indexed id, address indexed token, uint256 limit);
    event CallSet(address indexed account, bytes32 indexed id, address indexed target, bytes4 selector, bool allowed);
    event ValiditySet(address indexed account, bytes32 indexed id, uint48 validAfter, uint48 validUntil);
    event GuardianSet(address indexed account, bytes32 indexed id, address guardian);
    event Spent(
        address indexed account,
        bytes32 indexed id,
        address indexed token,
        uint256 period,
        uint256 amount,
        uint256 total
    );

    // ---------------------------------------------------------------- errors

    error AlreadyInstalled();
    error NotInstalled();
    error IsFrozen();
    error BadPeriod();
    error BadConfig();
    error NotGuardian();
    error UnsupportedCall();
    error SelfCall(address target);
    error CallNotAllowed(address target, bytes4 selector);
    error NoBudget(address token);
    error OverBudget(address token, uint256 period, uint256 total, uint256 limit);

    // ------------------------------------------------------------ install

    function _policyOninstall(bytes32 id, bytes calldata data) internal override {
        Config storage c = _configs[id][msg.sender];
        if (c.installed) revert AlreadyInstalled();
        InstallConfig memory cfg = abi.decode(data, (InstallConfig));
        if (cfg.validUntil != 0 && cfg.validUntil <= cfg.validAfter) revert BadConfig();

        c.validAfter = cfg.validAfter;
        c.validUntil = cfg.validUntil;
        c.periodStart = cfg.periodStart;
        c.periodLength = cfg.periodLength;
        c.countGas = cfg.countGas;
        c.guardian = cfg.guardian;
        c.frozen = false;
        c.installed = true;
        uint256 gen = c.generation;

        for (uint256 i; i < cfg.budgets.length; ++i) {
            Budget memory b = cfg.budgets[i];
            if (b.limit > type(uint248).max) revert BadConfig();
            _limits[gen][id][b.token][msg.sender] = Limit(true, uint248(b.limit));
            emit LimitSet(msg.sender, id, b.token, b.limit);
        }
        for (uint256 i; i < cfg.calls.length; ++i) {
            CallRule memory r = cfg.calls[i];
            _allowed[gen][id][r.target][r.selector][msg.sender] = true;
            emit CallSet(msg.sender, id, r.target, r.selector, true);
        }
        ++_installedCount[msg.sender];
        emit LeashInstalled(msg.sender, id, cfg.guardian);
    }

    function _policyOnUninstall(bytes32 id, bytes calldata) internal override {
        Config storage c = _configs[id][msg.sender];
        if (!c.installed) revert NotInstalled();
        uint32 next = c.generation + 1;
        delete _configs[id][msg.sender];
        c.generation = next;
        --_installedCount[msg.sender];
        emit LeashRemoved(msg.sender, id);
    }

    function isInitialized(address account) external view override returns (bool) {
        return _installedCount[account] > 0;
    }

    // ------------------------------------------------------------ validation

    /// @inheritdoc PolicyBase
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        Config storage c = _configs[id][msg.sender];
        if (!c.installed) revert NotInstalled();
        if (c.frozen) revert IsFrozen();

        uint256 period = userOp.signature.length >= 32 ? uint256(bytes32(userOp.signature[0:32])) : 0;
        (uint48 validAfter, uint48 validUntil) = _window(c, period);

        if (c.countGas && userOp.paymasterAndData.length < 20) {
            _spend(c, id, NATIVE, period, _maxGasCost(userOp));
        }

        bytes calldata callData = userOp.callData;
        if (callData.length >= 4 && bytes4(callData[0:4]) == EXECUTE_USEROP) callData = callData[4:];
        if (callData.length < 4 || bytes4(callData[0:4]) != EXECUTE) revert UnsupportedCall();

        bytes32 mode = bytes32(callData[4:36]);
        bytes calldata execData = _bytesArg(callData, 36);
        bytes1 callType = mode[0];
        bytes1 execType = mode[1];
        if (execType != EXECTYPE_DEFAULT && execType != EXECTYPE_TRY) revert UnsupportedCall();

        if (callType == CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes calldata data) = LibERC7579.decodeSingle(execData);
            _checkCall(c, id, period, target, value, data);
        } else if (callType == CALLTYPE_BATCH) {
            bytes32[] calldata pointers = LibERC7579.decodeBatch(execData);
            for (uint256 i; i < pointers.length; ++i) {
                (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
                _checkCall(c, id, period, target, value, data);
            }
        } else {
            revert UnsupportedCall(); // delegatecall, staticcall and anything else
        }

        return (uint256(validAfter) << 208) | (uint256(validUntil) << 160);
    }

    /// @dev An agent key never produces ERC-1271 signatures: a signed permit would move
    ///      tokens without passing through the budget.
    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure override returns (uint256) {
        return 1;
    }

    // ---------------------------------------------------------- owner controls
    // msg.sender is the account. The owner reaches these through a root-validated call.

    function setFrozen(bytes32 id, bool frozen) external {
        Config storage c = _installedConfig(id, msg.sender);
        c.frozen = frozen;
        emit Frozen(msg.sender, id, msg.sender, frozen);
    }

    function setLimit(bytes32 id, address token, uint256 limit, bool set) external {
        Config storage c = _installedConfig(id, msg.sender);
        if (limit > type(uint248).max) revert BadConfig();
        _limits[c.generation][id][token][msg.sender] = Limit(set, uint248(limit));
        emit LimitSet(msg.sender, id, token, set ? limit : 0);
    }

    function setCall(bytes32 id, address target, bytes4 selector, bool allowed) external {
        Config storage c = _installedConfig(id, msg.sender);
        _allowed[c.generation][id][target][selector][msg.sender] = allowed;
        emit CallSet(msg.sender, id, target, selector, allowed);
    }

    function setValidity(bytes32 id, uint48 validAfter, uint48 validUntil) external {
        Config storage c = _installedConfig(id, msg.sender);
        if (validUntil != 0 && validUntil <= validAfter) revert BadConfig();
        c.validAfter = validAfter;
        c.validUntil = validUntil;
        emit ValiditySet(msg.sender, id, validAfter, validUntil);
    }

    function setGuardian(bytes32 id, address guardian) external {
        Config storage c = _installedConfig(id, msg.sender);
        c.guardian = guardian;
        emit GuardianSet(msg.sender, id, guardian);
    }

    /// @notice The guardian's kill switch. It can only freeze; unfreezing is the owner's.
    function freeze(address account, bytes32 id) external {
        Config storage c = _installedConfig(id, account);
        if (msg.sender != c.guardian || c.guardian == address(0)) revert NotGuardian();
        c.frozen = true;
        emit Frozen(account, id, msg.sender, true);
    }

    // ------------------------------------------------------------------ views

    function configOf(address account, bytes32 id) external view returns (Config memory) {
        return _configs[id][account];
    }

    function limitOf(address account, bytes32 id, address token) external view returns (bool set, uint256 limit) {
        Limit memory l = _limits[_configs[id][account].generation][id][token][account];
        return (l.set, l.amount);
    }

    function spentOf(address account, bytes32 id, address token, uint256 period) external view returns (uint256) {
        return _spent[_configs[id][account].generation][id][token][period][account];
    }

    function isAllowed(address account, bytes32 id, address target, bytes4 selector) external view returns (bool) {
        uint256 gen = _configs[id][account].generation;
        return _allowed[gen][id][target][selector][account] || _allowed[gen][id][ANY_TARGET][selector][account];
    }

    /// @notice The period index for `timestamp`, which an agent puts in its signature slot.
    function periodAt(address account, bytes32 id, uint256 timestamp) external view returns (uint256) {
        Config storage c = _configs[id][account];
        if (c.periodLength == 0 || timestamp < c.periodStart) return 0;
        return (timestamp - c.periodStart) / c.periodLength;
    }

    // -------------------------------------------------------------- internals

    function _installedConfig(bytes32 id, address account) private view returns (Config storage c) {
        c = _configs[id][account];
        if (!c.installed) revert NotInstalled();
    }

    function _window(Config storage c, uint256 period) private view returns (uint48 validAfter, uint48 validUntil) {
        validAfter = c.validAfter;
        validUntil = c.validUntil;
        if (c.periodLength == 0) {
            if (period != 0) revert BadPeriod();
            return (validAfter, validUntil);
        }
        if (period > MAX_PERIOD) revert BadPeriod();
        uint256 start = uint256(c.periodStart) + period * c.periodLength;
        uint256 end = start + c.periodLength - 1;
        if (end > type(uint48).max) revert BadPeriod();
        if (start > validAfter) validAfter = uint48(start);
        if (validUntil == 0 || end < validUntil) validUntil = uint48(end);
        if (validUntil <= validAfter) revert BadPeriod();
    }

    function _checkCall(
        Config storage c,
        bytes32 id,
        uint256 period,
        address target,
        uint256 value,
        bytes calldata data
    ) private {
        if (target == msg.sender || target == address(this)) revert SelfCall(target);
        if (data.length != 0 && data.length < 4) revert UnsupportedCall();
        bytes4 selector = data.length == 0 ? bytes4(0) : bytes4(data[0:4]);

        if (value != 0) _spend(c, id, NATIVE, period, value);

        uint256 gen = c.generation;
        if (data.length != 0 && _limits[gen][id][target][msg.sender].set) {
            if (selector == TRANSFER || selector == APPROVE || selector == INCREASE_ALLOWANCE) {
                if (data.length < 68) revert UnsupportedCall();
                _spend(c, id, target, period, uint256(bytes32(data[36:68])));
                return;
            }
            if (selector == TRANSFER_FROM) {
                if (data.length < 100) revert UnsupportedCall();
                _spend(c, id, target, period, uint256(bytes32(data[68:100])));
                return;
            }
        }

        if (!_allowed[gen][id][target][selector][msg.sender] && !_allowed[gen][id][ANY_TARGET][selector][msg.sender]) {
            revert CallNotAllowed(target, selector);
        }
    }

    function _spend(Config storage c, bytes32 id, address token, uint256 period, uint256 amount) private {
        uint256 gen = c.generation;
        Limit memory l = _limits[gen][id][token][msg.sender];
        if (!l.set) revert NoBudget(token);
        uint256 total = _spent[gen][id][token][period][msg.sender] + amount;
        if (total > l.amount) revert OverBudget(token, period, total, l.amount);
        _spent[gen][id][token][period][msg.sender] = total;
        emit Spent(msg.sender, id, token, period, amount, total);
    }

    /// @dev Upper bound of what the account can be charged for this operation (v0.7).
    function _maxGasCost(PackedUserOperation calldata op) private pure returns (uint256) {
        uint256 verificationGas = uint128(bytes16(op.accountGasLimits));
        uint256 callGas = uint128(uint256(op.accountGasLimits));
        uint256 maxFeePerGas = uint128(uint256(op.gasFees));
        return (verificationGas + callGas + op.preVerificationGas) * maxFeePerGas;
    }

    /// @dev The `bytes` argument whose ABI head sits at `headAt` in `data` (offsets
    ///      count from byte 4, after the selector), as Solidity's decoder reads it.
    function _bytesArg(bytes calldata data, uint256 headAt) private pure returns (bytes calldata out) {
        uint256 offset = uint256(bytes32(data[headAt:headAt + 32]));
        uint256 lenAt = 4 + offset;
        uint256 len = uint256(bytes32(data[lenAt:lenAt + 32]));
        out = data[lenAt + 32:lenAt + 32 + len];
    }
}
