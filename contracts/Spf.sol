// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Library contract that emits events for decryption, using a callback function to handle the decryption result
library Spf {
    type SpfLibrary is bytes32;
    type SpfProgram is bytes32;
    type SpfCiphertextHash is bytes32;
    type SpfRunHandle is bytes32;

    enum SpfParamType {
        Ciphertext,
        CiphertextArray,
        OutputCiphertextArray,
        Plaintext,
        PlaintextArray
    }

    struct SpfParameter {
        uint256 metaData;
        bytes32[] payload;
    }

    struct SpfRun {
        SpfLibrary spfLibrary;
        SpfProgram program;
        SpfParameter[] parameters;
    }

    event RunProgramOnSpf(address indexed sender, SpfRun run);

    function createCiphertextParam(bytes32 hash) internal pure returns (SpfParameter memory) {
        uint256 metaData = uint8(SpfParamType.Ciphertext);
        metaData <<= 248;
        bytes32[] memory payload = new bytes32[](1);
        payload[0] = hash;
        return SpfParameter({metaData: metaData, payload: payload});
    }

    function createCiphertextArrayParam(bytes32[] memory hashes) internal pure returns (SpfParameter memory) {
        uint256 metaData = uint8(SpfParamType.CiphertextArray);
        metaData <<= 248;
        return SpfParameter({metaData: metaData, payload: hashes});
    }

    function createOutputCiphertextArrayParam(uint8 numBytes) internal pure returns (SpfParameter memory) {
        uint256 metaData = uint8(SpfParamType.OutputCiphertextArray);
        metaData <<= 8;
        metaData += numBytes;
        metaData <<= 240;
        return SpfParameter({metaData: metaData, payload: new bytes32[](0)});
    }

    function createPlaintextParam(uint8 bitWidth, uint128 value) internal pure returns (SpfParameter memory) {
        uint256 metaData = uint8(SpfParamType.Plaintext);
        metaData <<= 8;
        metaData += bitWidth;
        metaData <<= 128;
        metaData += value;
        metaData <<= 112;
        return SpfParameter({metaData: metaData, payload: new bytes32[](0)});
    }

    function createPlaintextArrayParam(uint8 bitWidth, uint128[] memory values)
        internal
        pure
        returns (SpfParameter memory)
    {
        uint256 metaData = uint8(SpfParamType.PlaintextArray);
        metaData <<= 8;
        metaData += bitWidth;
        metaData <<= 240;
        bytes32[] memory payload = new bytes32[](values.length);
        for (uint256 i = 0; i < values.length; i++) {
            payload[i] = bytes16(values[i]);
        }
        return SpfParameter({metaData: metaData, payload: payload});
    }

    function outputHash(SpfRun memory run) internal pure returns (bytes32) {
        return keccak256(abi.encode(run));
    }

    function requestSpf(SpfLibrary spfLibrary, SpfProgram program, SpfParameter[] memory inputs)
        internal
        returns (SpfRunHandle)
    {
        // Require at least one input
        require(inputs.length > 0, "SPF: No inputs provided");

        // Make sure we have output
        bool foundOutput = false;
        for (uint256 i = 0; i < inputs.length; i++) {
            SpfParamType paramType = SpfParamType(inputs[i].metaData >> 248);
            if (
                paramType == SpfParamType.CiphertextArray || paramType == SpfParamType.OutputCiphertextArray
                    || paramType == SpfParamType.PlaintextArray
            ) {
                foundOutput = true;
                break;
            }
        }
        require(foundOutput, "SPF: No outputs requested");

        SpfRun memory run = SpfRun({spfLibrary: spfLibrary, program: program, parameters: inputs});

        // Get hash of this struct
        bytes32 runHash = outputHash(run);

        emit RunProgramOnSpf(msg.sender, run);

        return SpfRunHandle.wrap(runHash);
    }

    function getOutputHandle(SpfRunHandle runHandle, uint8 index) internal pure returns (SpfCiphertextHash) {
        bytes32 outputHandle = keccak256(abi.encodePacked(runHandle, index));
        return SpfCiphertextHash.wrap(outputHandle);
    }
}
