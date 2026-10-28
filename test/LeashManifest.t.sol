// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {LeashManifest} from "../src/LeashManifest.sol";

contract LeashManifestTest is Test {
    LeashManifest manifest;

    function setUp() public {
        manifest = new LeashManifest(address(1), address(2), address(3), address(4), address(5));
    }

    function test_publishesAddresses() public view {
        assertEq(manifest.policy(), address(1));
        assertEq(manifest.signer(), address(2));
        assertEq(manifest.ownerValidator(), address(5));
        assertEq(manifest.owner(), address(this));
        assertEq(manifest.repository(), "https://github.com/Miracle656/leash");
    }

    function test_onlyOwnerTransfers() public {
        address next = makeAddr("next");
        vm.prank(next);
        vm.expectRevert(LeashManifest.NotOwner.selector);
        manifest.transferOwnership(next);

        manifest.transferOwnership(next);
        assertEq(manifest.owner(), next);
    }
}
