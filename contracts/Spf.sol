// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Library contract that emits events for decryption, using a callback function to handle the decryption result
library Spf {
    address public constant SPF_SERVICE = 0xa4723A446A80516d77D67B61b2911039a7e165b5;

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

    struct SpfParameterSignature {
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    struct SpfCiphertextAccessConfirmation {
        bytes32 ciphertextId;
        uint8 bitWidth;
        bytes access;
    }

    struct SpfRun {
        SpfLibrary spfLibrary;
        SpfProgram program;
        SpfParameter[] parameters;
    }

    enum SpfAccessChangeType {
        // Indicates adding admin
        AddAdmin,
        // Indicates adding run permission
        AllowRun,
        // Indicates adding decryption permission
        //
        // Also applies for recryption and downloading
        AllowDecrypt
    }

    enum SpfAccessEntityType {
        // Ethereum contract address, to be used with chain ID
        EthereumContract,
        // External account address
        External
    }

    // Users should use the following `addXxx` / `allowXxx` functions to create
    // parameters instead of handcrafting
    struct SpfAccessChange {
        uint256 metaData;
        bytes32[] payload;
    }

    struct SpfAccess {
        SpfCiphertextIdentifier ciphertext;
        SpfAccessChange[] changes;
    }

    event RunProgramOnSpf(address indexed requester, SpfRun run);

    event ChangeAccessOnSpf(address indexed requester, SpfAccess access);

    bytes32 private constant ACCESS_CONFIRMATION_TYPE_HASH =
        keccak256("SpfCiphertextAccessConfirmation(bytes32 ciphertextId,uint8 bitWidth,bytes access)");

    bytes32 private constant DOMAIN_SEPARATOR = keccak256(
        abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256(bytes("SPFServiceAccessConfirmation")),
            keccak256(bytes("1"))
        )
    );

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

    /// Modifier that checks that the parameter is a single ciphertext
    ///
    /// @param parameter the parameter to check
    modifier onlySingleCiphertext(SpfParameter memory parameter) {
        require(
            parameter.metaData == uint256(uint8(SpfParameterType.Ciphertext)) << 248 && parameter.payload.length == 1,
            "Given parameter is not a single ciphertext"
        );
        _;
    }

    /// Create a signature structure from signature raw bytes
    ///
    /// @param sig the signature raw bytes
    /// @return SpfParameterSignature the signature structure
    function createSignatureStruct(bytes memory sig) internal pure returns (SpfParameterSignature memory) {
        require(sig.length == 65, "The signature raw bytes must be 65 in length");

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        return SpfParameterSignature({r: r, s: s, v: v});
    }

    /// Verify if SPF service confirms a parameter with given bit width is owned by given wallet address
    ///
    /// @param parameter the parameter to verify
    /// @param bitWidth the bit width of the parameter
    /// @param sig the confirmation signature by SPF service
    /// @param externalOwner the owner to be verified
    function verifyCiphertextOwnedExternal(
        SpfParameter memory parameter,
        uint8 bitWidth,
        SpfParameterSignature memory sig,
        address externalOwner
    ) internal pure onlySingleCiphertext(parameter) {
        bytes32 hashStruct = keccak256(
            abi.encode(
                ACCESS_CONFIRMATION_TYPE_HASH,
                parameter.payload[0],
                bitWidth,
                keccak256(
                    bytes.concat(
                        bytes1(0x00), // admin (owner) permission type id
                        bytes1(0x01), // external address type id
                        bytes12(0x00), // padding
                        bytes20(externalOwner)
                    )
                )
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        require(ecrecover(digest, sig.v, sig.r, sig.s) == SPF_SERVICE, "Ciphertext is not confirmed by SPF service");
    }

    /// Verify if SPF service confirms a parameter with given bit width is owned by given contract address
    ///
    /// @param parameter the parameter to verify
    /// @param bitWidth the bit width of the parameter
    /// @param sig the confirmation signature by SPF service
    /// @param contractOwner the owner to be verified
    function verifyCiphertextOwnedContract(
        SpfParameter memory parameter,
        uint8 bitWidth,
        SpfParameterSignature memory sig,
        address contractOwner
    ) internal view onlySingleCiphertext(parameter) {
        bytes32 hashStruct = keccak256(
            abi.encode(
                ACCESS_CONFIRMATION_TYPE_HASH,
                parameter.payload[0],
                bitWidth,
                keccak256(
                    bytes.concat(
                        bytes1(0x00), // admin (owner) permission type id
                        bytes1(0x00), // contract address type id
                        bytes4(0x00), // padding for chain id
                        bytes8(uint64(block.chainid)),
                        bytes12(0x00), // padding
                        bytes20(contractOwner)
                    )
                )
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        require(ecrecover(digest, sig.v, sig.r, sig.s) == SPF_SERVICE, "Ciphertext is not confirmed by SPF service");
    }

    /// Verify if SPF service confirms a parameter with given bit width is owned by calling contract address
    ///
    /// @param parameter the parameter to verify
    /// @param bitWidth the bit width of the parameter
    /// @param sig the confirmation signature by SPF service
    function verifyCiphertextOwned(SpfParameter memory parameter, uint8 bitWidth, SpfParameterSignature memory sig)
        internal
        view
    {
        verifyCiphertextOwnedContract(parameter, bitWidth, sig, address(this));
    }

    /// Verify if SPF service confirms a parameter with given bit width is runnable by given wallet address
    ///
    /// @param parameter the parameter to verify
    /// @param bitWidth the bit width of the parameter
    /// @param sig the confirmation signature by SPF service
    /// @param externalRunner the runner to be verified
    /// @param spfLibrary the library to run on this ciphertext
    /// @param spfProgram the program in above library to run on this ciphertext
    function verifyCiphertextRunnableExternal(
        SpfParameter memory parameter,
        uint8 bitWidth,
        SpfParameterSignature memory sig,
        address externalRunner,
        SpfLibrary spfLibrary,
        SpfProgram spfProgram
    ) internal pure onlySingleCiphertext(parameter) {
        bytes32 hashStruct = keccak256(
            abi.encode(
                ACCESS_CONFIRMATION_TYPE_HASH,
                parameter.payload[0],
                bitWidth,
                keccak256(
                    bytes.concat(
                        bytes1(0x01), // run permission type id
                        bytes1(0x01), // external address type id
                        bytes12(0x00), // padding
                        bytes20(externalRunner),
                        SpfLibrary.unwrap(spfLibrary),
                        SpfProgram.unwrap(spfProgram)
                    )
                )
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        require(ecrecover(digest, sig.v, sig.r, sig.s) == SPF_SERVICE, "Ciphertext is not confirmed by SPF service");
    }

    /// Verify if SPF service confirms a parameter with given bit width is runnable by given contract address
    ///
    /// @param parameter the parameter to verify
    /// @param bitWidth the bit width of the parameter
    /// @param sig the confirmation signature by SPF service
    /// @param contractRunner the runner to be verified
    /// @param spfLibrary the library to run on this ciphertext
    /// @param spfProgram the program in above library to run on this ciphertext
    function verifyCiphertextRunnableContract(
        SpfParameter memory parameter,
        uint8 bitWidth,
        SpfParameterSignature memory sig,
        address contractRunner,
        SpfLibrary spfLibrary,
        SpfProgram spfProgram
    ) internal view onlySingleCiphertext(parameter) {
        bytes32 hashStruct = keccak256(
            abi.encode(
                ACCESS_CONFIRMATION_TYPE_HASH,
                parameter.payload[0],
                bitWidth,
                keccak256(
                    bytes.concat(
                        bytes1(0x01), // run permission type id
                        bytes1(0x00), // contract address type id
                        bytes4(0x00), // padding for chain id
                        bytes8(uint64(block.chainid)),
                        bytes20(contractRunner),
                        SpfLibrary.unwrap(spfLibrary),
                        SpfProgram.unwrap(spfProgram)
                    )
                )
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        require(ecrecover(digest, sig.v, sig.r, sig.s) == SPF_SERVICE, "Ciphertext is not confirmed by SPF service");
    }

    /// Verify if SPF service confirms a parameter with given bit width is runnable by calling contract address
    ///
    /// @param parameter the parameter to verify
    /// @param bitWidth the bit width of the parameter
    /// @param sig the confirmation signature by SPF service
    /// @param spfLibrary the library to run on this ciphertext
    /// @param spfProgram the program in above library to run on this ciphertext
    function verifyCiphertextRunnable(
        SpfParameter memory parameter,
        uint8 bitWidth,
        SpfParameterSignature memory sig,
        SpfLibrary spfLibrary,
        SpfProgram spfProgram
    ) internal view {
        verifyCiphertextRunnableContract(parameter, bitWidth, sig, address(this), spfLibrary, spfProgram);
    }

    /// Verify if SPF service confirms a parameter with given bit width is decryptable by given wallet address
    ///
    /// @param parameter the parameter to verify
    /// @param bitWidth the bit width of the parameter
    /// @param sig the confirmation signature by SPF service
    /// @param externalDecrypter the decrypter to be verified
    function verifyCiphertextDecryptableExternal(
        SpfParameter memory parameter,
        uint8 bitWidth,
        SpfParameterSignature memory sig,
        address externalDecrypter
    ) internal pure onlySingleCiphertext(parameter) {
        bytes32 hashStruct = keccak256(
            abi.encode(
                ACCESS_CONFIRMATION_TYPE_HASH,
                parameter.payload[0],
                bitWidth,
                keccak256(
                    bytes.concat(
                        bytes1(0x02), // decrypt permission type id
                        bytes1(0x01), // external address type id
                        bytes12(0x00), // padding
                        bytes20(externalDecrypter)
                    )
                )
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        require(ecrecover(digest, sig.v, sig.r, sig.s) == SPF_SERVICE, "Ciphertext is not confirmed by SPF service");
    }

    /// Verify if SPF service confirms a parameter with given bit width is decryptable by given contract address
    ///
    /// @param parameter the parameter to verify
    /// @param bitWidth the bit width of the parameter
    /// @param sig the confirmation signature by SPF service
    /// @param contractDecrypter the decrypter to be verified
    function verifyCiphertextDecryptableContract(
        SpfParameter memory parameter,
        uint8 bitWidth,
        SpfParameterSignature memory sig,
        address contractDecrypter
    ) internal view onlySingleCiphertext(parameter) {
        bytes32 hashStruct = keccak256(
            abi.encode(
                ACCESS_CONFIRMATION_TYPE_HASH,
                parameter.payload[0],
                bitWidth,
                keccak256(
                    bytes.concat(
                        bytes1(0x02), // decrypt permission type id
                        bytes1(0x00), // contract address type id
                        bytes4(0x00), // padding for chain id
                        bytes8(uint64(block.chainid)),
                        bytes20(contractDecrypter)
                    )
                )
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        require(ecrecover(digest, sig.v, sig.r, sig.s) == SPF_SERVICE, "Ciphertext is not confirmed by SPF service");
    }

    /// Verify if SPF service confirms a parameter with given bit width is decryptable by calling contract address
    ///
    /// @param parameter the parameter to verify
    /// @param bitWidth the bit width of the parameter
    /// @param sig the confirmation signature by SPF service
    function verifyCiphertextDecryptable(
        SpfParameter memory parameter,
        uint8 bitWidth,
        SpfParameterSignature memory sig
    ) internal view {
        verifyCiphertextDecryptableContract(parameter, bitWidth, sig, address(this));
    }

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
    /// @param bitWidth The bit width of the plaintext, must be one of 8, 16, 32, 64
    /// @param value The plaintext value, every value must be in the range with given bit width
    ///        for example if bit width is 8, then value must be between -128 to 255 (both ends inclusive)
    /// @return SpfParameter A parameter that corresponds to a single plaintext
    function createPlaintextParameter(uint8 bitWidth, int128 value) internal pure returns (SpfParameter memory) {
        uint256 metaData = uint8(SpfParameterType.Plaintext);
        metaData <<= 8;
        metaData += bitWidth;
        metaData <<= 240;
        bytes32[] memory payload = new bytes32[](1);
        payload[0] = bytes32(uint256(uint128(value)));
        return SpfParameter({metaData: metaData, payload: payload});
    }

    /// Create a parameter that corresponds to a plaintext array.
    ///
    /// @param bitWidth: the bit width of the plaintext values, must be one of 8, 16, 32, 64
    /// @param values: the plaintext values, every value must be in the range with given bit width
    ///        for example if bit width is 8, then every value must be between -128 to 255 (both ends inclusive)
    /// @return SpfParameter A parameter that corresponds to a plaintext array
    function createPlaintextArrayParameter(uint8 bitWidth, int128[] memory values)
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
            payload[i] = bytes32(uint256(uint128(values[i])));
        }
        return SpfParameter({metaData: metaData, payload: payload});
    }

    /// Create an access change that indicates adding admin to ciphertext, where
    /// the admin is an ethereum address with a chain ID
    ///
    /// @param chainId: the chain ID for the address to add as admin
    /// @param addr: the address to add as admin
    function addEthAdmin(uint64 chainId, address addr) internal pure returns (SpfAccessChange memory) {
        uint256 metaData = uint8(SpfAccessChangeType.AddAdmin);
        metaData <<= 8;
        metaData += uint8(SpfAccessEntityType.EthereumContract);
        metaData <<= 64;
        metaData += chainId;
        metaData <<= 176;
        bytes32[] memory payload = new bytes32[](1);
        payload[0] = bytes20(addr);
        return SpfAccessChange({metaData: metaData, payload: payload});
    }

    /// Create an access change that indicates adding admin to ciphertext, where
    /// the admin is an external address without a chain ID
    ///
    /// @param addr: the address to add as admin
    function addAdmin(address addr) internal pure returns (SpfAccessChange memory) {
        uint256 metaData = uint8(SpfAccessChangeType.AddAdmin);
        metaData <<= 8;
        metaData += uint8(SpfAccessEntityType.External);
        metaData <<= 240;
        bytes32[] memory payload = new bytes32[](1);
        payload[0] = bytes20(addr);
        return SpfAccessChange({metaData: metaData, payload: payload});
    }

    /// Create an access change that indicates adding run permission to ciphertext, where
    /// the runner is an ethereum address with a chain ID
    ///
    /// @param chainId: the chain ID for the address to allow run
    /// @param addr: the address to add as runner
    /// @param lib: the library (program binary) identifier that the permission applies to
    /// @param prog: the entry point function name that the permission applies to
    function allowEthRun(uint64 chainId, address addr, SpfLibrary lib, SpfProgram prog)
        internal
        pure
        returns (SpfAccessChange memory)
    {
        uint256 metaData = uint8(SpfAccessChangeType.AllowRun);
        metaData <<= 8;
        metaData += uint8(SpfAccessEntityType.EthereumContract);
        metaData <<= 64;
        metaData += chainId;
        metaData <<= 176;
        bytes32[] memory payload = new bytes32[](3);
        payload[0] = bytes20(addr);
        payload[1] = SpfLibrary.unwrap(lib);
        payload[2] = SpfProgram.unwrap(prog);
        return SpfAccessChange({metaData: metaData, payload: payload});
    }

    /// Create an access change that indicates adding run permission to ciphertext, where
    /// the runner is an external address without a chain ID
    ///
    /// @param addr: the address to add as runner
    /// @param lib: the library (program binary) identifier that the permission applies to
    /// @param prog: the entry point function name that the permission applies to
    function allowRun(address addr, SpfLibrary lib, SpfProgram prog) internal pure returns (SpfAccessChange memory) {
        uint256 metaData = uint8(SpfAccessChangeType.AllowRun);
        metaData <<= 8;
        metaData += uint8(SpfAccessEntityType.External);
        metaData <<= 240;
        bytes32[] memory payload = new bytes32[](3);
        payload[0] = bytes20(addr);
        payload[1] = SpfLibrary.unwrap(lib);
        payload[2] = SpfProgram.unwrap(prog);
        return SpfAccessChange({metaData: metaData, payload: payload});
    }

    /// Create an access change that indicates adding decrypt permission to ciphertext, where
    /// the decrypter is an ethereum address with a chain ID
    ///
    /// @param chainId: the chain ID for the address to allow decryption
    /// @param addr: the address to add as decryptor
    function allowEthDecrypt(uint64 chainId, address addr) internal pure returns (SpfAccessChange memory) {
        uint256 metaData = uint8(SpfAccessChangeType.AllowDecrypt);
        metaData <<= 8;
        metaData += uint8(SpfAccessEntityType.EthereumContract);
        metaData <<= 64;
        metaData += chainId;
        metaData <<= 176;
        bytes32[] memory payload = new bytes32[](1);
        payload[0] = bytes20(addr);
        return SpfAccessChange({metaData: metaData, payload: payload});
    }

    /// Create an access change that indicates adding decrypt permission to ciphertext, where
    /// the decrypter is an external address without a chain ID
    ///
    /// @param addr: the address to add as decryptor
    function allowDecrypt(address addr) internal pure returns (SpfAccessChange memory) {
        uint256 metaData = uint8(SpfAccessChangeType.AllowDecrypt);
        metaData <<= 8;
        metaData += uint8(SpfAccessEntityType.External);
        metaData <<= 240;
        bytes32[] memory payload = new bytes32[](1);
        payload[0] = bytes20(addr);
        return SpfAccessChange({metaData: metaData, payload: payload});
    }

    /// Turns a parameter from output into identifier understandable by the decryption service
    ///
    /// @param param The SpfParameter returned from `getOutputHandle`
    /// @return bytes32 The identifier for decryption service to use
    function passToDecryption(SpfParameter memory param) internal pure onlySingleCiphertext(param) returns (bytes32) {
        return param.payload[0];
    }

    /// Generates a unique hash for a specific SPF program run with a given contract as the runner.
    ///
    /// @dev This function is mostly useful in testing, you generally want `getRunHandleAsContract` in production.
    ///
    /// @param run The SpfRun struct containing the program and parameters
    /// @param contract_runner The contract that runs the program
    /// @return bytes32 The identifier for a specific run of the SPF program by runner
    function getRunHandleWithContractRunner(SpfRun memory run, address contract_runner)
        internal
        view
        returns (SpfRunHandle)
    {
        return SpfRunHandle.wrap(
            keccak256(bytes.concat(abi.encode(run), bytes8(uint64(block.chainid)), bytes20(contract_runner)))
        );
    }

    /// Generates a unique hash for a specific SPF program run with this contract as the runner.
    ///
    /// @param run The SpfRun struct containing the program and parameters by this contract
    /// @return bytes32 The identifier for a specific run of the SPF program
    function getRunHandleAsContract(SpfRun memory run) internal view returns (SpfRunHandle) {
        return getRunHandleWithContractRunner(run, address(this));
    }

    /// Generates a unique hash for a specific SPF program run with the transaction sender as the runner.
    ///
    /// @param run The SpfRun struct containing the program and parameters by this contract
    /// @return bytes32 The identifier for a specific run of the SPF program
    function getRunHandleAsSender(SpfRun memory run) internal view returns (SpfRunHandle) {
        return SpfRunHandle.wrap(keccak256(bytes.concat(abi.encode(run), bytes20(msg.sender))));
    }

    /// Requests execution of a Secure Processing Framework (SPF) program with
    /// the provided parameters.
    ///
    /// @dev This function emits a RunProgramOnSpf event that triggers execution
    ///      of the specified program by an off-chain SPF service. The function
    ///      validates that at least one parameter is provided and that there is
    ///      at least one parameter that can be used for output.
    ///
    /// @param requester the entity that initiated the request for permission
    ///        check purposes, can be either `msg.sender` or `address(this)`,
    ///        other values are not accepted and cause the execution request
    ///        to be dismissed
    /// @param spfLibrary The identifier of the SPF library containing the
    ///        program to be executed.
    /// @param program The identifier of the specific program to execute within
    ///        the library.
    /// @param params Array of parameters to pass to the program, including both
    ///        input and output parameters.
    ///
    /// @return SpfRun The run object
    function requestRun(address requester, SpfLibrary spfLibrary, SpfProgram program, SpfParameter[] memory params)
        internal
        returns (SpfRun memory)
    {
        // Require at least one parameter
        require(params.length > 0, "SPF: No parameters provided");

        // Make sure we have output, note ciphertext and plaintext arrays can also be used as output
        bool foundOutput = false;
        for (uint256 i = 0; i < params.length; i++) {
            SpfParameterType parameterType = SpfParameterType(params[i].metaData >> 248);
            if (parameterType == SpfParameterType.OutputCiphertextArray) {
                foundOutput = true;
                break;
            }
        }
        require(foundOutput, "SPF: No outputs requested");

        SpfRun memory run = SpfRun({spfLibrary: spfLibrary, program: program, parameters: params});

        emit RunProgramOnSpf(requester, run);

        return run;
    }

    /// Requests execution of a Secure Processing Framework (SPF) program with
    /// the provided parameters with the transaction sender as the requester.
    ///
    /// @dev see `requestRun(address, SpfLibrary, SpfProgram, SpfParameter[] memory)`
    function requestRunAsSender(SpfLibrary spfLibrary, SpfProgram program, SpfParameter[] memory params)
        internal
        returns (SpfRunHandle)
    {
        return getRunHandleAsSender(requestRun(msg.sender, spfLibrary, program, params));
    }

    /// Requests execution of a Secure Processing Framework (SPF) program with
    /// the provided parameters with the contract as the requester.
    ///
    /// @dev see `requestRun(address, SpfLibrary, SpfProgram, SpfParameter[] memory)`
    function requestRunAsContract(SpfLibrary spfLibrary, SpfProgram program, SpfParameter[] memory params)
        internal
        returns (SpfRunHandle)
    {
        return getRunHandleAsContract(requestRun(address(this), spfLibrary, program, params));
    }

    /// Requests changes to the access control list (ACL) of a specific ciphertext.
    ///
    /// @dev This function emits a ChangeAccessOnSpf event that triggers ACL updates
    ///      for the specified ciphertext by the off-chain SPF service. The returned
    ///      value is the identifier for the new ciphertext with the requested ACL
    ///      changes.
    ///
    /// @param requester the entity that initiated the request for permission
    ///        check purposes, can be either `msg.sender` or `address(this)`,
    ///        other values are not accepted and cause the ACL change request
    ///        to be dismissed
    /// @param ciphertext A single ciphertext parameter whose ACL will be modified.
    ///        The function will revert if this is not a single ciphertext (e.g.,
    ///        arrays or other parameter types).
    /// @param changes Array of access control changes to apply to the ciphertext.
    ///        Can include adding admins, granting run permissions, or allowing
    ///        decryption. Use helper functions like addAdmin(), allowRun(), and
    ///        allowDecrypt() (or their Eth variants) to create these changes.
    ///        Must contain at least one change or the function will revert.
    ///
    /// @return SpfParameter A unique ciphertext with the new ACL as requested.
    ///         The actual ciphertext content remains unchanged.
    ///
    /// @custom:example
    /// ```solidity
    /// // Grant multiple permissions to a ciphertext
    /// Spf.SpfAccessChange[] memory changes = new Spf.SpfAccessChange[](2);
    /// changes[0] = Spf.allowEthRun(1, contractAddress, library, program);
    /// changes[1] = Spf.allowDecrypt(userAddress);
    ///
    /// // Assume an existing SpfParameter `ciphertext` representing a single ciphertext.
    /// Spf.SpfParameter memory newSpfParameter = Spf.requestAcl(ciphertext, changes);
    /// ```
    ///
    /// @custom:emits ChangeAccessOnSpf(address, SpfAccess) Contains the ciphertext
    ///               ID and all requested ACL changes for off-chain processing
    /// @custom:reverts "Given parameter is not a single ciphertext" if the parameter
    ///                 is not a single ciphertext type
    /// @custom:reverts "SPF: No changes specified" if the changes array is empty
    function requestAcl(address requester, SpfParameter memory ciphertext, SpfAccessChange[] memory changes)
        internal
        onlySingleCiphertext(ciphertext)
        returns (SpfParameter memory)
    {
        SpfCiphertextIdentifier cid = SpfCiphertextIdentifier.wrap(ciphertext.payload[0]);
        // Require at least one change
        require(changes.length > 0, "SPF: No changes specified");

        SpfAccess memory acc = SpfAccess({ciphertext: cid, changes: changes});

        // Get hash of this struct
        bytes32 accHash = keccak256(abi.encode(acc));

        emit ChangeAccessOnSpf(requester, acc);

        return createCiphertextParameter(SpfCiphertextIdentifier.wrap(accHash));
    }

    /// Requests changes to the access control list (ACL) of a specific ciphertext
    /// with the transaction sender as the requester.
    ///
    /// @dev see `requestAcl(address, SpfParameter memory, SpfAccessChange[] memory)`
    function requestAclAsSender(SpfParameter memory ciphertext, SpfAccessChange[] memory changes)
        internal
        onlySingleCiphertext(ciphertext)
        returns (SpfParameter memory)
    {
        return requestAcl(msg.sender, ciphertext, changes);
    }

    /// Requests changes to the access control list (ACL) of a specific ciphertext
    /// with the contract as the requester.
    ///
    /// @dev see `requestAcl(address, SpfParameter memory, SpfAccessChange[] memory)`
    function requestAclAsContract(SpfParameter memory ciphertext, SpfAccessChange[] memory changes)
        internal
        onlySingleCiphertext(ciphertext)
        returns (SpfParameter memory)
    {
        return requestAcl(address(this), ciphertext, changes);
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
