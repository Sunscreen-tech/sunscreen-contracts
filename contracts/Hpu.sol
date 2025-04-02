// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Library contract that emits events for decryption, using a callback function to handle the decryption result
library Hpu {
    type HpuLibrary is bytes32;
    type HpuProgram is bytes32;
    type HpuParameter is bytes32;
    type HpuRunHandle is bytes32;

    struct HpuRun {
        HpuLibrary hpuLibrary;
        HpuProgram program;
        HpuParameter[] parameters;
    }

    event RunProgramOnHpu(address indexed sender, HpuRun run);

    function outputHash(HpuRun memory run) internal pure returns (bytes32) {
        return keccak256(abi.encode(run));
    }

    function requestHpu(HpuLibrary hpuLibrary, HpuProgram program, HpuParameter[] memory inputs, uint256 numOutputs)
        internal
        returns (HpuRunHandle)
    {
        // Require at least one input
        require(inputs.length > 0, "HPU: No inputs provided");

        // Require at least one output
        require(numOutputs > 0, "HPU: No outputs requested");

        // Append numOutput number of zeros to the inputs
        HpuParameter[] memory extendedParameters = new HpuParameter[](inputs.length + numOutputs);
        for (uint256 i = 0; i < inputs.length; i++) {
            extendedParameters[i] = inputs[i];
        }
        for (uint256 i = inputs.length; i < extendedParameters.length; i++) {
            extendedParameters[i] = HpuParameter.wrap(0);
        }

        HpuRun memory run = HpuRun({hpuLibrary: hpuLibrary, program: program, parameters: extendedParameters});

        // Get hash of this struct
        bytes32 runHash = outputHash(run);

        emit RunProgramOnHpu(msg.sender, run);

        return HpuRunHandle.wrap(runHash);
    }

    function getOutputHandle(HpuRunHandle runHandle, uint8 index) internal pure returns (HpuParameter) {
        bytes32 outputHandle = keccak256(abi.encodePacked(runHandle, index));
        return HpuParameter.wrap(outputHandle);
    }
}
