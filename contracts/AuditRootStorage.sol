// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuditRootStorage {
    struct AuditRoot {
        bytes32 merkleRoot;
        uint256 timestamp;
    }

    // Mapping: companyID -> weekID -> AuditRoot
    mapping(string => mapping(string => AuditRoot)) public roots;

    event RootStored(string companyID, string weekID, bytes32 root, uint256 timestamp);

    function storeRoot(string memory companyID, string memory weekID, bytes32 root) public {
        roots[companyID][weekID] = AuditRoot(root, block.timestamp);
        emit RootStored(companyID, weekID, root, block.timestamp);
    }

    function getRoot(string memory companyID, string memory weekID) public view returns (bytes32, uint256) {
        AuditRoot storage audit = roots[companyID][weekID];
        return (audit.merkleRoot, audit.timestamp);
    }
}