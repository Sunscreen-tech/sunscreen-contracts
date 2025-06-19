// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Library contract that emits events for decryption, using a callback function to handle the decryption result
library Spf {
    type SpfLibrary is bytes32;
    type SpfProgram is bytes32;
    type SpfParameter is bytes32;
    type SpfRunHandle is bytes32;

    struct SpfRun {
        SpfLibrary spfLibrary;
        SpfProgram program;
        SpfParameter[] parameters;
    }

    event RunProgramOnSpf(address indexed sender, SpfRun run);

    function outputHash(SpfRun memory run) internal pure returns (bytes32) {
        return keccak256(abi.encode(run));
    }

    function requestSpf(SpfLibrary spfLibrary, SpfProgram program, SpfParameter[] memory inputs, uint256 numOutputs)
        internal
        returns (SpfRunHandle)
    {
        // Require at least one input
        require(inputs.length > 0, "SPF: No inputs provided");

        // Require at least one output
        require(numOutputs > 0, "SPF: No outputs requested");

        // Append numOutput number of zeros to the inputs
        SpfParameter[] memory extendedParameters = new SpfParameter[](inputs.length + numOutputs);
        for (uint256 i = 0; i < inputs.length; i++) {
            extendedParameters[i] = inputs[i];
        }
        for (uint256 i = inputs.length; i < extendedParameters.length; i++) {
            extendedParameters[i] = SpfParameter.wrap(0);
        }

        SpfRun memory run = SpfRun({spfLibrary: spfLibrary, program: program, parameters: extendedParameters});

        // Get hash of this struct
        bytes32 runHash = outputHash(run);

        emit RunProgramOnSpf(msg.sender, run);

        return SpfRunHandle.wrap(runHash);
    }

    function getOutputHandle(SpfRunHandle runHandle, uint8 index) internal pure returns (SpfParameter) {
        bytes32 outputHandle = keccak256(abi.encodePacked(runHandle, index));
        return SpfParameter.wrap(outputHandle);
    }
}
