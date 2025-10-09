// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Library contract that emits events for decryption, using a callback function to handle the decryption result
contract TfheThresholdDecryption {
    address public constant THRESHOLD_DECRYPTION_SERVICE = 0xB79e28b5DC528DDCa75b2f1Df6d234C2A00Db866;

    event DecryptCiphertextOnSpf(address indexed requester, bytes4 callbackSelector, bytes32 ciphertextId);

    /// Request the threshold decryption of a given parameter.
    ///
    /// @param requester The entity initiating the request, either `msg.sender` or `address(this)`, others invalid
    /// @param callbackSelector The selector of the callback function to handle the decryption result.
    /// @param ciphertextId The raw identifier of ciphertext to be decrypted.
    function requestDecryption(address requester, bytes4 callbackSelector, bytes32 ciphertextId) internal {
        emit DecryptCiphertextOnSpf(requester, callbackSelector, ciphertextId);
    }

    /// Request the threshold decryption of a given parameter with the transaction sender as the requester.
    ///
    /// @dev see `requestDecryption(address, bytes4, bytes32)`
    function requestDecryptionAsSender(bytes4 callbackSelector, bytes32 ciphertextId) internal {
        emit DecryptCiphertextOnSpf(msg.sender, callbackSelector, ciphertextId);
    }

    /// Request the threshold decryption of a given parameter with the contract as the requester.
    ///
    /// @dev see `requestDecryption(address, bytes4, bytes32)`
    function requestDecryptionAsContract(bytes4 callbackSelector, bytes32 ciphertextId) internal {
        emit DecryptCiphertextOnSpf(address(this), callbackSelector, ciphertextId);
    }

    /// Modifier to restrict access to the threshold decryption service
    modifier onlyThresholdDecryption() {
        require(
            msg.sender == THRESHOLD_DECRYPTION_SERVICE, "Only the threshold decryption service can call this function"
        );
        _;
    }
}
