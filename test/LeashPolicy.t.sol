// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LeashBase, Service} from "./LeashBase.sol";
import {LeashPolicy} from "../src/LeashPolicy.sol";
import {Kernel} from "kernel/Kernel.sol";
import {Execution} from "kernel/types/Structs.sol";
import {ExecMode} from "kernel/types/Types.sol";
import {PackedUserOperation} from "kernel/interfaces/PackedUserOperation.sol";
import {ERC20} from "solady/tokens/ERC20.sol";

contract LeashPolicyTest is LeashBase {
    function setUp() public override {
        super.setUp();
        installLeash(defaultConfig());
    }

    // --------------------------------------------------------------- install

    function test_installRecordsConfig() public view {
        LeashPolicy.Config memory c = policy.configOf(address(kernel), permissionId());
        assertTrue(c.installed);
        assertEq(c.guardian, guardian);
        assertEq(c.periodLength, 1 days);
        (bool set, uint256 limit) = policy.limitOf(address(kernel), permissionId(), address(token));
        assertTrue(set);
        assertEq(limit, 50e6);
        assertEq(signer.agentOf(address(kernel), permissionId()), agent);
        assertTrue(policy.isAllowed(address(kernel), permissionId(), address(service), Service.ping.selector));
    }

    // ---------------------------------------------------------- native budget

    function test_agentPaysWithinBudget() public {
        runAgent(single(shop, 0.4 ether, ""), 0);
        runAgent(single(address(service), 0.6 ether, abi.encodeCall(Service.ping, ())), 0);
        assertEq(shop.balance, 0.4 ether);
        assertEq(service.pings(), 1);
        assertEq(policy.spentOf(address(kernel), permissionId(), address(0), 0), 1 ether);
    }

    function test_nativeOverBudgetRejected() public {
        runAgent(single(shop, 0.7 ether, ""), 0);
        PackedUserOperation memory op = agentOp(single(shop, 0.4 ether, ""), 0);
        expectPolicyRevert(abi.encodeWithSelector(LeashPolicy.OverBudget.selector, address(0), 0, 1.1 ether, 1 ether));
        _submit(op);
    }

    // ----------------------------------------------------------- token budget

    function test_tokenTransferCounts() public {
        runAgent(single(address(token), 0, abi.encodeCall(ERC20.transfer, (shop, 30e6))), 0);
        assertEq(token.balanceOf(shop), 30e6);
        PackedUserOperation memory op =
            agentOp(single(address(token), 0, abi.encodeCall(ERC20.transfer, (shop, 21e6))), 0);
        expectPolicyRevert(abi.encodeWithSelector(LeashPolicy.OverBudget.selector, address(token), 0, 51e6, 50e6));
        _submit(op);
    }

    /// An agent cannot dodge the cap by approving a spender and letting it pull.
    function test_approveCountsAgainstBudget() public {
        PackedUserOperation memory op =
            agentOp(single(address(token), 0, abi.encodeCall(ERC20.approve, (address(service), type(uint256).max))), 0);
        expectPolicyRevert(
            abi.encodeWithSelector(LeashPolicy.OverBudget.selector, address(token), 0, type(uint256).max, 50e6)
        );
        _submit(op);

        runAgent(single(address(token), 0, abi.encodeCall(ERC20.approve, (address(service), 40e6))), 0);
        service.pull(token, address(kernel), 40e6);
        assertEq(token.balanceOf(address(service)), 40e6);
        assertEq(policy.spentOf(address(kernel), permissionId(), address(token), 0), 40e6);
    }

    function test_batchIsSummed() public {
        Execution[] memory calls = new Execution[](3);
        calls[0] = Execution(address(token), 0, abi.encodeCall(ERC20.transfer, (shop, 20e6)));
        calls[1] = Execution(address(token), 0, abi.encodeCall(ERC20.transfer, (shop, 20e6)));
        calls[2] = Execution(address(token), 0, abi.encodeCall(ERC20.transfer, (shop, 20e6)));
        PackedUserOperation memory op = agentOp(batch(calls), 0);
        expectPolicyRevert(abi.encodeWithSelector(LeashPolicy.OverBudget.selector, address(token), 0, 60e6, 50e6));
        _submit(op);

        Execution[] memory ok = new Execution[](2);
        ok[0] = Execution(address(token), 0, abi.encodeCall(ERC20.transfer, (shop, 25e6)));
        ok[1] = Execution(address(service), 0.1 ether, abi.encodeCall(Service.ping, ()));
        runAgent(batch(ok), 0);
        assertEq(token.balanceOf(shop), 25e6);
        assertEq(service.pings(), 1);
    }

    // ----------------------------------------------------------------- calls

    function test_unlistedCallRejected() public {
        bytes memory data = abi.encodeCall(Service.pull, (token, address(kernel), 1));
        PackedUserOperation memory op = agentOp(single(address(service), 0, data), 0);
        expectPolicyRevert(
            abi.encodeWithSelector(LeashPolicy.CallNotAllowed.selector, address(service), Service.pull.selector)
        );
        _submit(op);
    }

    function test_plainTransferToUnlistedAddressRejected() public {
        address stranger = makeAddr("stranger");
        PackedUserOperation memory op = agentOp(single(stranger, 0.1 ether, ""), 0);
        expectPolicyRevert(abi.encodeWithSelector(LeashPolicy.CallNotAllowed.selector, stranger, bytes4(0)));
        _submit(op);
    }

    function test_selfCallRejected() public {
        bytes memory data = abi.encodeCall(Kernel.grantAccess, (vId(), Kernel.installModule.selector, true));
        PackedUserOperation memory op = agentOp(single(address(kernel), 0, data), 0);
        expectPolicyRevert(abi.encodeWithSelector(LeashPolicy.SelfCall.selector, address(kernel)));
        _submit(op);
    }

    function test_policyCallRejected() public {
        bytes memory data = abi.encodeCall(LeashPolicy.setFrozen, (permissionId(), false));
        PackedUserOperation memory op = agentOp(single(address(policy), 0, data), 0);
        expectPolicyRevert(abi.encodeWithSelector(LeashPolicy.SelfCall.selector, address(policy)));
        _submit(op);
    }

    function test_delegatecallRejected() public {
        bytes memory data = abi.encodeCall(
            Kernel.execute,
            (ExecMode.wrap(bytes32(uint256(0xff) << 248)), abi.encodePacked(address(service), hex"5c36b186"))
        );
        PackedUserOperation memory op = agentOp(data, 0);
        expectPolicyRevert(abi.encodeWithSelector(LeashPolicy.UnsupportedCall.selector));
        _submit(op);
    }

    function test_unbudgetedTokenNeedsRule() public {
        LeashPolicy.InstallConfig memory cfg = defaultConfig();
        assertTrue(cfg.budgets.length > 0);
        // Drop the token budget: a transfer is now just an unlisted call.
        ownerCall(address(policy), abi.encodeCall(LeashPolicy.setLimit, (permissionId(), address(token), 0, false)));
        bytes memory data = abi.encodeCall(ERC20.transfer, (shop, 1));
        PackedUserOperation memory op = agentOp(single(address(token), 0, data), 0);
        expectPolicyRevert(
            abi.encodeWithSelector(LeashPolicy.CallNotAllowed.selector, address(token), ERC20.transfer.selector)
        );
        _submit(op);
    }

    // --------------------------------------------------------------- periods

    function test_budgetResetsNextPeriod() public {
        runAgent(single(shop, 1 ether, ""), 0);
        vm.warp(block.timestamp + 1 days);
        assertEq(policy.periodAt(address(kernel), permissionId(), block.timestamp), 1);
        runAgent(single(shop, 1 ether, ""), 1);
        assertEq(shop.balance, 2 ether);
    }

    function test_futurePeriodNotDue() public {
        PackedUserOperation memory op = agentOp(single(shop, 1 ether, ""), 1);
        expectOutOfWindow();
        _submit(op);
    }

    function test_pastPeriodExpired() public {
        vm.warp(block.timestamp + 1 days);
        PackedUserOperation memory op = agentOp(single(shop, 1 ether, ""), 0);
        expectOutOfWindow();
        _submit(op);
    }

    function test_absurdPeriodRejected() public {
        PackedUserOperation memory op = agentOp(single(shop, 1, ""), type(uint256).max);
        expectPolicyRevert(abi.encodeWithSelector(LeashPolicy.BadPeriod.selector));
        _submit(op);
    }

    function test_expiry() public {
        ownerCall(
            address(policy),
            abi.encodeCall(LeashPolicy.setValidity, (permissionId(), 0, uint48(block.timestamp + 1 hours)))
        );
        runAgent(single(shop, 0.1 ether, ""), 0);
        vm.warp(block.timestamp + 2 hours);
        PackedUserOperation memory op = agentOp(single(shop, 0.1 ether, ""), 0);
        expectOutOfWindow();
        _submit(op);
    }

    // ---------------------------------------------------------- kill switch

    function test_guardianFreezes() public {
        vm.prank(guardian);
        policy.freeze(address(kernel), permissionId());
        PackedUserOperation memory op = agentOp(single(shop, 0.1 ether, ""), 0);
        expectPolicyRevert(abi.encodeWithSelector(LeashPolicy.IsFrozen.selector));
        _submit(op);

        ownerCall(address(policy), abi.encodeCall(LeashPolicy.setFrozen, (permissionId(), false)));
        runAgent(single(shop, 0.1 ether, ""), 0);
        assertEq(shop.balance, 0.1 ether);
    }

    function test_onlyGuardianFreezes() public {
        vm.expectRevert(LeashPolicy.NotGuardian.selector);
        vm.prank(agent);
        policy.freeze(address(kernel), permissionId());
    }

    function test_guardianCannotUnfreeze() public {
        vm.prank(guardian);
        policy.freeze(address(kernel), permissionId());
        // setFrozen is keyed by msg.sender, so the guardian has no config to touch.
        vm.expectRevert(LeashPolicy.NotInstalled.selector);
        vm.prank(guardian);
        policy.setFrozen(permissionId(), false);
        assertTrue(policy.configOf(address(kernel), permissionId()).frozen);
    }

    // -------------------------------------------------------------- signer

    function test_wrongKeyRejected() public {
        (, uint256 otherKey) = makeAddrAndKey("intruder");
        PackedUserOperation memory op = agentOpSigned(single(shop, 0.1 ether, ""), 0, otherKey);
        expectBadSignature();
        _submit(op);
    }

    function test_agentCannotSignForAccount() public {
        bytes32 hash = keccak256("permit");
        bytes memory sig = abi.encodePacked(bytes1(0x02), PERMISSION_ID, _sign(agentKey, hash));
        vm.expectRevert();
        kernel.isValidSignature(hash, sig);
    }

    // ------------------------------------------------------------------ gas

    function test_gasCountsWhenEnabled() public {
        LeashPolicy.InstallConfig memory cfg = defaultConfig();
        cfg.countGas = true;
        _reinstall(cfg);

        // Gas limits 1M + 1M + 100k at 1 wei.
        uint256 maxGas = 2_100_000;
        runAgent(single(shop, 0, ""), 0);
        assertEq(policy.spentOf(address(kernel), permissionId(), address(0), 0), maxGas);
    }

    // ------------------------------------------------------------ uninstall

    function test_reinstallStartsClean() public {
        runAgent(single(shop, 1 ether, ""), 0);
        _reinstall(defaultConfig());
        assertEq(policy.spentOf(address(kernel), permissionId(), address(0), 0), 0);
        runAgent(single(shop, 1 ether, ""), 0);
        assertEq(shop.balance, 2 ether);
    }

    function _reinstall(LeashPolicy.InstallConfig memory cfg) internal {
        bytes[] memory deinit = new bytes[](2);
        _ownerOp(abi.encodeCall(Kernel.uninstallValidation, (vId(), abi.encode(deinit), hex"")));
        assertFalse(policy.configOf(address(kernel), permissionId()).installed);
        installLeash(cfg);
    }
}
