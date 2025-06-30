// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Library contract that emits events for decryption, using a callback function to handle the decryption result
library Spf {
    type SpfLibrary is bytes32;
    type SpfProgram is bytes32;
    type SpfCiphertextIdentifier is bytes32;
    type SpfRunHandle is bytes32;

    enum SpfParameterType {
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

    // Users should use the following `createXxxParam` functions to create
    // parameters instead of handcrafting
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

    // Trivial encryption has no security so by using the ciphertext identifiers below
    // everyone knows the data you are using, we provide just 0 and 1 here

    /// Trivial ciphertext encoding the value 0 with 8 bits
    SpfCiphertextIdentifier constant TRIVIAL_ZERO_8_BIT =
        SpfCiphertextIdentifier.wrap(0x0ba77c8f6b3c744f64b85a0bb205ddb1aa53c5f8d5a68c04141c91e2afc9ebae);

    /// Trivial ciphertext encoding the value 0 with 16 bits
    SpfCiphertextIdentifier constant TRIVIAL_ZERO_16_BIT =
        SpfCiphertextIdentifier.wrap(0x49b72fb6643ea599ea1fd3bcfa81260e40983ee185e67271e49cb76beeb998dc);

    /// Trivial ciphertext encoding the value 0 with 32 bits
    SpfCiphertextIdentifier constant TRIVIAL_ZERO_32_BIT =
        SpfCiphertextIdentifier.wrap(0x297dabf2fbad4b6577e45722d3e1bf92c682388aaacefbadd834511240a52c1d);

    /// Trivial ciphertext encoding the value 0 with 64 bits
    SpfCiphertextIdentifier constant TRIVIAL_ZERO_64_BIT =
        SpfCiphertextIdentifier.wrap(0xb77f1b48164a4729f4a0a669e284d4abaa28e5e5891aa043effd52e5f2e9f3d1);

    /// Trivial ciphertext encoding the value 1 with 8 bits
    SpfCiphertextIdentifier constant TRIVIAL_ONE_8_BIT =
        SpfCiphertextIdentifier.wrap(0x23de99e2dca5d26d8cf8f8caeb620e8d94fb417e54543127448befbf87dd3680);

    /// Trivial ciphertext encoding the value 1 with 16 bits
    SpfCiphertextIdentifier constant TRIVIAL_ONE_16_BIT =
        SpfCiphertextIdentifier.wrap(0x4e27107de8cf8be7b48c3bc32f85739e2d8141eebd4e8144c722772530fb3054);

    /// Trivial ciphertext encoding the value 1 with 32 bits
    SpfCiphertextIdentifier constant TRIVIAL_ONE_32_BIT =
        SpfCiphertextIdentifier.wrap(0x1d833c57b9b3129ce94c091b863f6021ca7cc83f4b985bf4f6ddb0165eb27c6e);

    /// Trivial ciphertext encoding the value 1 with 64 bits
    SpfCiphertextIdentifier constant TRIVIAL_ONE_64_BIT =
        SpfCiphertextIdentifier.wrap(0x0d7e18449071e3683ef83b234781f2657ef8f840974d7f8c8e1101d997fbcb8f);

    /// Create a trivial zero ciphertext for the specified bit width.
    function createTrivialZeroCiphertextParameter(uint8 bitWidth) internal pure returns (SpfParameter memory) {
        if (bitWidth == 8) {
            return createCiphertextParameter(TRIVIAL_ZERO_8_BIT);
        } else if (bitWidth == 16) {
            return createCiphertextParameter(TRIVIAL_ZERO_16_BIT);
        } else if (bitWidth == 32) {
            return createCiphertextParameter(TRIVIAL_ZERO_32_BIT);
        } else if (bitWidth == 64) {
            return createCiphertextParameter(TRIVIAL_ZERO_64_BIT);
        } else {
            revert("Unsupported bit width for trivial zero ciphertext");
        }
    }

    /// Create a trivial one ciphertext for the specified bit width.
    function createTrivialOneCiphertextParameter(uint8 bitWidth) internal pure returns (SpfParameter memory) {
        if (bitWidth == 8) {
            return createCiphertextParameter(TRIVIAL_ONE_8_BIT);
        } else if (bitWidth == 16) {
            return createCiphertextParameter(TRIVIAL_ONE_16_BIT);
        } else if (bitWidth == 32) {
            return createCiphertextParameter(TRIVIAL_ONE_32_BIT);
        } else if (bitWidth == 64) {
            return createCiphertextParameter(TRIVIAL_ONE_64_BIT);
        } else {
            revert("Unsupported bit width for trivial one ciphertext");
        }
    }

    /// Create a parameter that corresponds to a single ciphertext.
    ///
    /// @param identifier The ciphertext identifier
    /// @return SpfParameter A parameter that corresponds to a single ciphertext
    function createCiphertextParameter(SpfCiphertextIdentifier identifier)
        internal
        pure
        returns (SpfParameter memory)
    {
        uint256 metaData = uint8(SpfParameterType.Ciphertext);
        metaData <<= 248;
        bytes32[] memory payload = new bytes32[](1);
        payload[0] = SpfCiphertextIdentifier.unwrap(identifier);
        return SpfParameter({metaData: metaData, payload: payload});
    }

    /// Create a parameter that corresponds to a ciphertext array.
    ///
    /// @param identifiers array of ciphertext identifiers
    /// @return SpfParameter A parameter that corresponds to a ciphertext array
    function createCiphertextArrayParameter(SpfCiphertextIdentifier[] memory identifiers)
        internal
        pure
        returns (SpfParameter memory)
    {
        uint256 metaData = uint8(SpfParameterType.CiphertextArray);
        metaData <<= 248;
        bytes32[] memory payload;
        assembly {
            payload := identifiers
        }
        return SpfParameter({metaData: metaData, payload: payload});
    }

    /// Create a parameter that corresponds to an output ciphertext
    ///
    /// @param bitWidth The number of bits in this output ciphertext
    /// @return SpfParameter A parameter that corresponds to an output ciphertext
    function createOutputCiphertextParameter(uint8 bitWidth) internal pure returns (SpfParameter memory) {
        uint256 metaData = uint8(SpfParameterType.OutputCiphertextArray);
        metaData <<= 8;
        metaData += bitWidth;
        metaData <<= 8;
        metaData += 1;
        metaData <<= 232;
        return SpfParameter({metaData: metaData, payload: new bytes32[](0)});
    }

    /// Create a parameter that corresponds to an output ciphertext array
    ///
    /// @param bitWidth The number of bits in each element of this output ciphertext array
    /// @param numElements The number of elements in this output ciphertext array
    /// @return SpfParameter A parameter that corresponds to an output ciphertext array
    function createOutputCiphertextArrayParameter(uint8 bitWidth, uint8 numElements)
        internal
        pure
        returns (SpfParameter memory)
    {
        uint256 metaData = uint8(SpfParameterType.OutputCiphertextArray);
        metaData <<= 8;
        metaData += bitWidth;
        metaData <<= 8;
        metaData += numElements;
        metaData <<= 232;
        return SpfParameter({metaData: metaData, payload: new bytes32[](0)});
    }

    /// Create a parameter that corresponds to a single plaintext.
    ///
    /// @param bitWidth The bit width of the plaintext.
    /// @param value The plaintext value
    /// @return SpfParameter A parameter that corresponds to a single plaintext
    function createPlaintextParameter(uint8 bitWidth, uint256 value) internal pure returns (SpfParameter memory) {
        uint256 metaData = uint8(SpfParameterType.Plaintext);
        metaData <<= 8;
        metaData += bitWidth;
        metaData <<= 240;
        bytes32[] memory payload = new bytes32[](1);
        payload[0] = bytes32(value);
        return SpfParameter({metaData: metaData, payload: payload});
    }

    /// Create a parameter that corresponds to a plaintext array.
    ///
    /// @param bitWidth: the bit width of the plaintext values
    /// @param values: the plaintext values
    /// @return SpfParameter A parameter that corresponds to a plaintext array
    function createPlaintextArrayParameter(uint8 bitWidth, uint256[] memory values)
        internal
        pure
        returns (SpfParameter memory)
    {
        uint256 metaData = uint8(SpfParameterType.PlaintextArray);
        metaData <<= 8;
        metaData += bitWidth;
        metaData <<= 240;
        bytes32[] memory payload = new bytes32[](values.length);
        for (uint256 i = 0; i < values.length; i++) {
            payload[i] = bytes32(values[i]);
        }
        return SpfParameter({metaData: metaData, payload: payload});
    }

    /// Generates a unique hash for a specific output value of an SPF program run.
    ///
    /// @param run The SpfRun struct containing the program and parameters
    /// @return bytes32 The identifier for a specific run of the SPF program
    function outputHash(SpfRun memory run) internal pure returns (bytes32) {
        return keccak256(abi.encode(run));
    }

    /// Requests execution of a Secure Processing Framework (SPF) program with
    /// the provided parameters.
    ///
    /// @dev This function emits a RunProgramOnSpf event that triggers execution
    ///      of the specified program by an off-chain SPF service. The function
    ///      validates that at least one input is provided and that there is
    ///      at least one parameter that can be used for output.
    ///
    /// @param spfLibrary The identifier of the SPF library containing the
    ///        program to be executed.
    /// @param program The identifier of the specific program to execute within
    ///        the library.
    /// @param inputs Array of parameters to pass to the program, including both
    ///        input and output parameters.
    ///
    /// @return SpfRunHandle A unique identifier for this specific program
    ///         execution request that can be used to retrieve results with
    ///         the getOutputHandle function.
    function requestSpf(SpfLibrary spfLibrary, SpfProgram program, SpfParameter[] memory inputs)
        internal
        returns (SpfRunHandle)
    {
        // Require at least one input
        require(inputs.length > 0, "SPF: No inputs provided");

        // Make sure we have output, note ciphertext and plaintext arrays can also be used as output
        bool foundOutput = false;
        for (uint256 i = 0; i < inputs.length; i++) {
            SpfParameterType parameterType = SpfParameterType(inputs[i].metaData >> 248);
            if (parameterType == SpfParameterType.OutputCiphertextArray) {
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

    /// Generates a unique ciphertext identifier for a specific output from an
    /// SPF program execution
    ///
    /// @param runHandle The handle returned by the requestSpf function
    /// @param index The zero-based index of the output parameter to retrieve
    /// @return SpfCiphertextIdentifier A unique identifier for accessing the
    ///         specified output from the program execution
    function getOutputHandle(SpfRunHandle runHandle, uint8 index) internal pure returns (SpfParameter memory) {
        bytes32 outputHandle = keccak256(abi.encodePacked(runHandle, index));
        SpfCiphertextIdentifier identifier = SpfCiphertextIdentifier.wrap(outputHandle);

        return createCiphertextParameter(identifier);
    }

    /// Checks if a given SpfParameter is uninitialized. This happens when you
    /// define a parameter but have not set it to anything yet.
    ///
    /// @param param The SpfParameter to check
    /// @return bool True if the parameter is uninitialized, false otherwise
    function isUninitializedParameter(SpfParameter memory param) internal pure returns (bool) {
        return param.metaData == 0 && param.payload.length == 0;
    }
}
