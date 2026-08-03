// SPDX-License-Identifier: MIT
// sec-audit fixture — INTENTIONALLY VULNERABLE. Textbook anti-patterns for
// the Solidity heuristics; never deploy this contract.
pragma solidity ^0.8.0;

contract Vault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // sol-tx-origin: authentication via tx.origin (phishable).
    function isOwner() internal view returns (bool) {
        return tx.origin == owner;
    }

    // sol-missing-access-control: anyone can take ownership.
    function setOwner(address next) public {
        owner = next;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // sol-reentrancy: external call before the balance is written.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    // sol-unchecked-call: .send return value ignored.
    function sweep(address payable to) external {
        to.send(address(this).balance);
    }

    // sol-selfdestruct: rug primitive, gated only by the phishable check.
    function shutdown() external {
        require(isOwner(), "not owner");
        selfdestruct(payable(owner));
    }
}
