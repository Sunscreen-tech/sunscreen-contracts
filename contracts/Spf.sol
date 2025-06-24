// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Library contract that emits events for decryption, using a callback function to handle the decryption result
library Spf {
    type SpfLibrary is bytes32;
    type SpfProgram is bytes32;
    type SpfParameter is bytes32;
    type SpfCiphertextHash is bytes32;
    type SpfPlaintext is uint128;
    type SpfRunHandle is bytes32;

    enum SpfParamType {
        Ciphertext,
        CiphertextArray,
        OutputCiphertextArray,
        Plaintext,
        PlaintextArray
    }

    struct SpfParamDescription {
        SpfParamType param_type;
        // this field has no meaning if `param_type` is `Ciphertext` or `CiphertextArray`
        // this field means the number of bytes in the output if `param_type` is `OutputCiphertextArray`
        // this field means the bit width of the plaintext if `param_type` is `Plaintext` or `PlaintextArray`
        uint8 meta_data;
        // this field has no meaning if `param_type` is `OutputCiphertextArray` or `Plaintext` or `PlaintextArray`
        // this field contains the ciphertext has if if `param_type` is `Ciphertext` or `CiphertextArray`
        // in the former case, this field should contain only one ciphertext hash
        SpfCiphertextHash[] ciphertexts;
        // this field has no meaning if `param_type` is `OutputCiphertextArray` or `Ciphertext` or `CiphertextArray`
        // this field contains the ciphertext has if if `param_type` is `Plaintext` or `PlaintextArray`
        // in the former case, this field should contain only one plaintext
        SpfPlaintext[] plaintexts;
    }

    struct SpfRun {
        SpfLibrary spfLibrary;
        SpfProgram program;
        SpfParameter[] parameters;
    }

    event RunProgramOnSpf(address indexed sender, SpfRun run);

    function outputHash(SpfRun memory run) internal pure returns (bytes32) {
        return keccak256(abi.encode(run));
    }

    function requestSpf(SpfLibrary spfLibrary, SpfProgram program, SpfParamDescription[] memory inputs)
        internal
        returns (SpfRunHandle)
    {
        // Require at least one input
        require(inputs.length > 0, "SPF: No inputs provided");

        // Figure out the extra length needed for parameter array
        // By the way make sure we have output
        uint256 extraLen = 0;
        bool foundOutput = false;
        for (uint256 i = 0; i < inputs.length; i++) {
            if (inputs[i].param_type == SpfParamType.Ciphertext) {
                extraLen += 1;
            } else if (inputs[i].param_type == SpfParamType.CiphertextArray) {
                extraLen += inputs[i].ciphertexts.length;
                foundOutput = true;
            } else if (inputs[i].param_type == SpfParamType.PlaintextArray) {
                extraLen += inputs[i].plaintexts.length;
                foundOutput = true;
            } else if (inputs[i].param_type == SpfParamType.OutputCiphertextArray) {
                foundOutput = true;
            }
        }
        require(foundOutput, "SPF: No outputs requested");

        SpfParameter[] memory parameters = new SpfParameter[](inputs.length + extraLen);

        uint256 index = 0;
        for (uint256 i = 0; i < inputs.length; i++) {
            if (inputs[i].param_type == SpfParamType.Ciphertext) {
                parameters[index] = SpfParameter.wrap(0);
                index += 1;
                parameters[index] = SpfParameter.wrap(SpfCiphertextHash.unwrap(inputs[i].ciphertexts[0]));
                index += 1;
            } else if (inputs[i].param_type == SpfParamType.CiphertextArray) {
                bytes32 control_data = bytes1(uint8(1));
                bytes32 size = bytes1(uint8(inputs[i].ciphertexts.length));
                control_data |= size >> 8;
                parameters[index] = SpfParameter.wrap(control_data);
                index += 1;
                for (uint256 j = 0; j < inputs[i].ciphertexts.length; j++) {
                    parameters[index] = SpfParameter.wrap(SpfCiphertextHash.unwrap(inputs[i].ciphertexts[j]));
                    index += 1;
                }
            } else if (inputs[i].param_type == SpfParamType.OutputCiphertextArray) {
                bytes32 control_data = bytes1(uint8(2));
                control_data |= bytes32(bytes1(inputs[i].meta_data)) >> 8;
                parameters[index] = SpfParameter.wrap(control_data);
                index += 1;
            } else if (inputs[i].param_type == SpfParamType.Plaintext) {
                bytes32 control_data = bytes1(uint8(3));
                control_data |= bytes32(bytes1(inputs[i].meta_data)) >> 8;
                control_data |= bytes32(bytes16(SpfPlaintext.unwrap(inputs[i].plaintexts[0]))) >> 16;
                parameters[index] = SpfParameter.wrap(control_data);
                index += 1;
            } else {
                bytes32 control_data = bytes1(uint8(4));
                control_data |= bytes32(bytes1(inputs[i].meta_data)) >> 8;
                control_data |= bytes32(bytes1(uint8(inputs[i].plaintexts.length))) >> 16;
                parameters[index] = SpfParameter.wrap(control_data);
                index += 1;
                for (uint256 j = 0; j < inputs[i].plaintexts.length; j++) {
                    bytes32 val = bytes16(SpfPlaintext.unwrap(inputs[i].plaintexts[j]));
                    parameters[index] = SpfParameter.wrap(val);
                    index += 1;
                }
            }
        }

        SpfRun memory run = SpfRun({spfLibrary: spfLibrary, program: program, parameters: parameters});

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
