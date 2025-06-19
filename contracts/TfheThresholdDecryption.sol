// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Spf.sol";

// Library contract that emits events for decryption, using a callback function to handle the decryption result
contract TfheThresholdDecryption {
    event RequestThresholdDecryption(
        address indexed sender, address contractAddress, bytes4 callbackSelector, bytes32 param
    );

    function requestThresholdDecryption(bytes4 callbackSelector, bytes32 param) internal {
        emit RequestThresholdDecryption(msg.sender, address(this), callbackSelector, param);
    }

    modifier onlyThresholdDecryption() {
        require(
            msg.sender == 0xB79e28b5DC528DDCa75b2f1Df6d234C2A00Db866,
            "Only the threshold decryption service can call this function"
        );
        _;
    }
}
