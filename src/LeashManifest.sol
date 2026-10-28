// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title  LeashManifest
/// @notice The official Leash addresses on this chain, published by the project's owner so
///         clients and agents can discover them on-chain, and so the project can prove control
///         on provenance registries such as Tally.
contract LeashManifest {
    string public constant repository = "https://github.com/Miracle656/leash";

    address public immutable policy;
    address public immutable signer;
    address public immutable kernelImplementation;
    address public immutable kernelFactory;
    address public immutable ownerValidator;
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();

    constructor(
        address policy_,
        address signer_,
        address kernelImplementation_,
        address kernelFactory_,
        address ownerValidator_
    ) {
        policy = policy_;
        signer = signer_;
        kernelImplementation = kernelImplementation_;
        kernelFactory = kernelFactory_;
        ownerValidator = ownerValidator_;
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
