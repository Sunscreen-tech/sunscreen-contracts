// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Library contract that emits events for decryption, using a callback function to handle the decryption result
library Spf {
    type SpfLibrary is bytes32;
    type SpfProgram is bytes32;
    type SpfCiphertextIdentifier is bytes32;
    type SpfRunHandle is bytes32;

    enum SpfParamType {
        // Indicates the parameter is a single "pass by value" ciphertext
        //
        // e.g. `[[clang::encrypted]] uint16_t val`
        Ciphertext,
        // Indicates the parameter is a ciphertext array passed in as a pointer
        //
        // e.g. `[[clang::encrypted]] uint16_t *ciphertext`
        //
        // This is used for arrays and pointers (which can be understood as array of size 1)
        // If you use it as an array, you may need a plaintext parameter for the size,
        // unless the size is already hardcoded in the program itself.
        //
        // This can be used for both input and output
        CiphertextArray,
        // Indicates the parameter is a ciphertext pointer to receive output
        //
        // e.g. `[[clang::encrypted]] uint16_t *output_ciphertext`
        //
        // This can only be used for output
        OutputCiphertextArray,
        // Indicates the parameter is a single "pass by value" ciphertext
        //
        // e.g. `uint16_t val`
        Plaintext,
        // Indicates the parameter is a plaintext array passed in as a pointer
        //
        // e.g. `uint16_t *plaintext`
        //
        // This is used for arrays and pointers (which can be understood as array of size 1)
        // If you use it as an array, you may need a plaintext parameter for the size,
        // unless the size is already hardcoded in the program itself.
        //
        // This can be used for both input and output
        PlaintextArray
    }

    // Users should use the following `createXxxParam` functions to create parameters instead of handcrafting
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

    // Create a parameter that corresponds to a single ciphertext
    //
    // identifier: the ciphertext identifier obtained through uploading to SPF service or running a program
    function createCiphertextParam(SpfCiphertextIdentifier identifier) internal pure returns (SpfParameter memory) {
        uint256 metaData = uint8(SpfParamType.Ciphertext);
        metaData <<= 248;
        bytes32[] memory payload = new bytes32[](1);
        payload[0] = SpfCiphertextIdentifier.unwrap(identifier);
        return SpfParameter({metaData: metaData, payload: payload});
    }

    // Create a parameter that corresponds to a ciphertext array
    //
    // identifiers: array of ciphertext identifiers obtained through uploading to SPF service or running a program
    function createCiphertextArrayParam(SpfCiphertextIdentifier[] memory identifiers)
        internal
        pure
        returns (SpfParameter memory)
    {
        uint256 metaData = uint8(SpfParamType.CiphertextArray);
        metaData <<= 248;
        bytes32[] memory payload;
        assembly {
            payload := identifiers
        }
        return SpfParameter({metaData: metaData, payload: payload});
    }

    // Create a parameter that corresponds to an output ciphertext array
    //
    // numBytes: the number of bytes in this output array (not number of elements as we do not know the size of each element)
    function createOutputCiphertextArrayParam(uint8 numBytes) internal pure returns (SpfParameter memory) {
        uint256 metaData = uint8(SpfParamType.OutputCiphertextArray);
        metaData <<= 8;
        metaData += numBytes;
        metaData <<= 240;
        return SpfParameter({metaData: metaData, payload: new bytes32[](0)});
    }

    // Create a parameter that corresponds to a single plaintext
    //
    // bitWidth: the bit width of this plaintext, up to 256 (0 means 256), note current backend only supports up to 128
    // value: the plaintext value
    function createPlaintextParam(uint8 bitWidth, uint256 value) internal pure returns (SpfParameter memory) {
        uint256 metaData = uint8(SpfParamType.Plaintext);
        metaData <<= 8;
        metaData += bitWidth;
        metaData <<= 240;
        bytes32[] memory payload = new bytes32[](1);
        payload[0] = bytes32(value);
        return SpfParameter({metaData: metaData, payload: payload});
    }

    // Create a parameter that corresponds to a plaintext array
    //
    // bitWidth: the bit width of all plaintexts in this array, up to 256 (0 means 256), note current backend only supports up to 128
    // values: the plaintext values in an array
    function createPlaintextArrayParam(uint8 bitWidth, uint256[] memory values)
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
            payload[i] = bytes32(values[i]);
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

        // Make sure we have output, note ciphertext and plaintext arrays can also be used as output
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

    function getOutputHandle(SpfRunHandle runHandle, uint8 index) internal pure returns (SpfCiphertextIdentifier) {
        bytes32 outputHandle = keccak256(abi.encodePacked(runHandle, index));
        return SpfCiphertextIdentifier.wrap(outputHandle);
    }
}
