// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Kernel} from "kernel/Kernel.sol";
import {KernelFactory} from "kernel/factory/KernelFactory.sol";
import {ECDSAValidator} from "kernel/validator/ECDSAValidator.sol";
import {IEntryPoint} from "kernel/interfaces/IEntryPoint.sol";

import {LeashPolicy} from "../src/LeashPolicy.sol";
import {LeashSigner} from "../src/LeashSigner.sol";

/// @notice Deploys the Leash stack with CREATE2, so it lands at the same addresses on
///         every chain. Anything already deployed is skipped.
///
///         forge script script/Deploy.s.sol --rpc-url bohr --broadcast
contract Deploy is Script {
    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 constant SALT = keccak256("leash.v1");

    function run() external {
        require(ENTRYPOINT.code.length > 0, "EntryPoint v0.7 missing");
        uint256 key = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(key);
        address kernelImpl = _deploy("Kernel", abi.encodePacked(type(Kernel).creationCode, abi.encode(ENTRYPOINT)));
        address factory =
            _deploy("KernelFactory", abi.encodePacked(type(KernelFactory).creationCode, abi.encode(kernelImpl)));
        address ownerValidator = _deploy("ECDSAValidator", type(ECDSAValidator).creationCode);
        address policy = _deploy("LeashPolicy", type(LeashPolicy).creationCode);
        address signer = _deploy("LeashSigner", type(LeashSigner).creationCode);
        vm.stopBroadcast();

        string memory o = "deployment";
        vm.serializeUint(o, "chainId", block.chainid);
        vm.serializeAddress(o, "entryPoint", ENTRYPOINT);
        vm.serializeAddress(o, "kernelImpl", kernelImpl);
        vm.serializeAddress(o, "kernelFactory", factory);
        vm.serializeAddress(o, "ecdsaValidator", ownerValidator);
        vm.serializeAddress(o, "leashPolicy", policy);
        string memory json = vm.serializeAddress(o, "leashSigner", signer);
        vm.writeJson(json, string.concat("deployments/", vm.toString(block.chainid), ".json"));
    }

    function _deploy(string memory name, bytes memory initCode) internal returns (address addr) {
        addr = vm.computeCreate2Address(SALT, keccak256(initCode), CREATE2_DEPLOYER);
        if (addr.code.length > 0) {
            console.log("%s already at %s", name, addr);
            return addr;
        }
        (bool ok,) = CREATE2_DEPLOYER.call(abi.encodePacked(SALT, initCode));
        require(ok && addr.code.length > 0, string.concat(name, " deploy failed"));
        console.log("%s deployed at %s", name, addr);
    }
}
