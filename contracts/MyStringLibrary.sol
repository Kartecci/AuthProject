// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

library MyStringLibrary {
    function isEqual(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }
}