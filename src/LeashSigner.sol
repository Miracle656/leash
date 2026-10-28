// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SignerBase} from "kernel/sdk/moduleBase/SignerBase.sol";
import {PackedUserOperation} from "kernel/interfaces/PackedUserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

/// @title  LeashSigner
/// @notice The agent's key for a Kernel v3 permission: a plain ECDSA address.
/// @dev    User operations are signed as an EIP-191 personal message over the user
///         operation hash, which every wallet library can produce. The key can never
///         sign ERC-1271 messages for the account (see LeashPolicy).
contract LeashSigner is SignerBase {
    mapping(bytes32 id => mapping(address account => address)) private _signers;
    mapping(address account => uint256) private _installedCount;

    event AgentKeySet(address indexed account, bytes32 indexed id, address agent);

    error AlreadyInstalled();
    error NotInstalled();
    error BadSigner();

    function _signerOninstall(bytes32 id, bytes calldata data) internal override {
        if (_signers[id][msg.sender] != address(0)) revert AlreadyInstalled();
        if (data.length != 20) revert BadSigner();
        address agent = address(bytes20(data[0:20]));
        if (agent == address(0)) revert BadSigner();
        _signers[id][msg.sender] = agent;
        ++_installedCount[msg.sender];
        emit AgentKeySet(msg.sender, id, agent);
    }

    function _signerOnUninstall(bytes32 id, bytes calldata) internal override {
        if (_signers[id][msg.sender] == address(0)) revert NotInstalled();
        delete _signers[id][msg.sender];
        --_installedCount[msg.sender];
        emit AgentKeySet(msg.sender, id, address(0));
    }

    function isInitialized(address account) external view override returns (bool) {
        return _installedCount[account] > 0;
    }

    function agentOf(address account, bytes32 id) external view returns (address) {
        return _signers[id][account];
    }

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        address agent = _signers[id][msg.sender];
        if (agent == address(0)) return 1;
        address recovered = ECDSA.tryRecoverCalldata(ECDSA.toEthSignedMessageHash(userOpHash), userOp.signature);
        return recovered == agent ? 0 : 1;
    }

    function checkSignature(bytes32, address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return 0xffffffff;
    }
}
