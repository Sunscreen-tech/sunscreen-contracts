// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/TfheThresholdDecryption.sol";
import "../contracts/Spf.sol";

// Mock contract that inherits from TfheThresholdDecryption
contract MockDecryptionUser is TfheThresholdDecryption {
    using Spf for *;

    // Store decryption results for verification
    uint256 public lastDecryptedValue;
    bool public decryptionReceived;

    // Library and program to use for SPF
    Spf.SpfLibrary public spfLibrary;
    Spf.SpfProgram public program;

    constructor(Spf.SpfLibrary _spfLibrary, Spf.SpfProgram _program) {
        spfLibrary = _spfLibrary;
        program = _program;
    }

    // Function to execute an SPF program and request decryption of its output
    function executeAndRequestDecryption(Spf.SpfParamDescription[] calldata inputs)
        external
        returns (Spf.SpfRunHandle)
    {
        // Run the SPF program
        Spf.SpfRunHandle runHandle = Spf.requestSpf(spfLibrary, program, inputs);

        // Get the zeroth output handle
        Spf.SpfCiphertextHash outputHandle = Spf.getOutputHandle(runHandle, 0);

        // Request threshold decryption of the output
        requestThresholdDecryption(this.handleDecryptionResult.selector, Spf.SpfCiphertextHash.unwrap(outputHandle));

        return runHandle;
    }

    // Callback function for threshold decryption
    function handleDecryptionResult(uint256 decryptedValue) external onlyThresholdDecryption {
        lastDecryptedValue = decryptedValue;
        decryptionReceived = true;
    }

    // Reset the decryption state (for testing)
    function resetDecryptionState() external {
        lastDecryptedValue = 0;
        decryptionReceived = false;
    }
}

contract TfheThresholdDecryptionTest is Test {
    using Spf for *;

    // Constants for testing
    address constant THRESHOLD_DECRYPTION_SERVICE = 0xB79e28b5DC528DDCa75b2f1Df6d234C2A00Db866;
    uint256 constant DECRYPTED_VALUE = 123;
    Spf.SpfLibrary constant SPF_LIBRARY =
        Spf.SpfLibrary.wrap(0x61dc6dc7d7d82fa0e9870bf697cbb69544fdb1cc0ddac1427fc863b29e129860);
    Spf.SpfProgram constant PROGRAM =
        Spf.SpfProgram.wrap(0x70726F6772616D00000000000000000000000000000000000000000000000000);
    Spf.SpfParameter constant PARAM_ZERO = Spf.SpfParameter.wrap(0);
    Spf.SpfCiphertextHash constant PARAM_1 =
        Spf.SpfCiphertextHash.wrap(0x363ec54649521a2aca55a792954a4678698076f38cab85a06bb5de1ef8b20a7c);
    Spf.SpfCiphertextHash constant PARAM_2 =
        Spf.SpfCiphertextHash.wrap(0x13ca007bae631cf35724b1d4c92ac26cd8fa49c2e1b30cc7b886f86d8a579525);

    // Test contract instances
    MockDecryptionUser public mockUser;

    // Events to test against
    event RequestThresholdDecryption(
        address indexed sender, address contractAddress, bytes4 callbackSelector, Spf.SpfCiphertextHash param
    );

    event RunProgramOnSpf(address indexed sender, Spf.SpfRun run);

    function setUp() public {
        // Deploy the mock user contract
        mockUser = new MockDecryptionUser(SPF_LIBRARY, PROGRAM);
    }

    function test_ExecuteAndRequestDecryption() public {
        // Create test input parameters
        Spf.SpfCiphertextHash[][] memory hashes = new Spf.SpfCiphertextHash[][](2);
        hashes[0] = new Spf.SpfCiphertextHash[](1);
        hashes[0][0] = PARAM_1;
        hashes[1] = new Spf.SpfCiphertextHash[](1);
        hashes[1][0] = PARAM_2;

        Spf.SpfParamDescription[] memory inputs = new Spf.SpfParamDescription[](3);
        inputs[0] = Spf.SpfParamDescription({
            param_type: Spf.SpfParamType.Ciphertext,
            meta_data: 0,
            ciphertexts: hashes[0],
            plaintexts: new Spf.SpfPlaintext[](0)
        });
        inputs[1] = Spf.SpfParamDescription({
            param_type: Spf.SpfParamType.Ciphertext,
            meta_data: 0,
            ciphertexts: hashes[1],
            plaintexts: new Spf.SpfPlaintext[](0)
        });
        inputs[2] = Spf.SpfParamDescription({
            param_type: Spf.SpfParamType.OutputCiphertextArray,
            meta_data: 4,
            ciphertexts: new Spf.SpfCiphertextHash[](0),
            plaintexts: new Spf.SpfPlaintext[](0)
        });

        // Expect RunProgramOnSpf event
        vm.expectEmit(true, true, false, true);

        // Calculate expected parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](5);
        expectedParams[0] = PARAM_ZERO;
        expectedParams[1] = Spf.SpfParameter.wrap(Spf.SpfCiphertextHash.unwrap(hashes[0][0]));
        expectedParams[2] = PARAM_ZERO;
        expectedParams[3] = Spf.SpfParameter.wrap(Spf.SpfCiphertextHash.unwrap(hashes[1][0]));
        expectedParams[4] = Spf.SpfParameter.wrap(0x0204000000000000000000000000000000000000000000000000000000000000);

        // Create expected SpfRun
        Spf.SpfRun memory expectedRun =
            Spf.SpfRun({spfLibrary: mockUser.spfLibrary(), program: mockUser.program(), parameters: expectedParams});

        emit RunProgramOnSpf(address(this), expectedRun);

        // Also expect RequestThresholdDecryption event
        vm.expectEmit(true, true, true, true);

        // Calculate expected output handle
        Spf.SpfRunHandle expectedRunHandle = Spf.SpfRunHandle.wrap(keccak256(abi.encode(expectedRun)));
        Spf.SpfCiphertextHash expectedOutputHandle = Spf.getOutputHandle(expectedRunHandle, 0);

        emit RequestThresholdDecryption(
            address(this), address(mockUser), MockDecryptionUser.handleDecryptionResult.selector, expectedOutputHandle
        );

        // Execute the function
        Spf.SpfRunHandle runHandle = mockUser.executeAndRequestDecryption(inputs);

        // Verify returned run handle
        assertEq(Spf.SpfRunHandle.unwrap(runHandle), keccak256(abi.encode(expectedRun)));

        // Verify that no decryption has been received yet
        assertFalse(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), 0);

        vm.prank(THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(DECRYPTED_VALUE);

        // Verify that decryption was received and stored correctly
        assertTrue(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), DECRYPTED_VALUE);
    }

    function test_OnlyThresholdDecryption() public {
        // Try to call the callback function from an unauthorized address
        vm.expectRevert("Only the threshold decryption service can call this function");
        mockUser.handleDecryptionResult(DECRYPTED_VALUE);

        // Verify it works when called from the threshold decryption service
        vm.prank(THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(DECRYPTED_VALUE);

        assertTrue(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), DECRYPTED_VALUE);
    }

    function test_MultipleOutputs() public {
        // Create test input parameters
        Spf.SpfCiphertextHash[] memory hashes = new Spf.SpfCiphertextHash[](1);
        hashes[0] = PARAM_1;

        Spf.SpfParamDescription[] memory inputs = new Spf.SpfParamDescription[](2);
        inputs[0] = Spf.SpfParamDescription({
            param_type: Spf.SpfParamType.Ciphertext,
            meta_data: 0,
            ciphertexts: hashes,
            plaintexts: new Spf.SpfPlaintext[](0)
        });
        inputs[1] = Spf.SpfParamDescription({
            param_type: Spf.SpfParamType.OutputCiphertextArray,
            meta_data: 12,
            ciphertexts: new Spf.SpfCiphertextHash[](0),
            plaintexts: new Spf.SpfPlaintext[](0)
        });

        // Execute the function
        Spf.SpfRunHandle runHandle = mockUser.executeAndRequestDecryption(inputs);

        // Verify we can get all output handles
        Spf.SpfCiphertextHash output0 = Spf.getOutputHandle(runHandle, 0);
        Spf.SpfCiphertextHash output1 = Spf.getOutputHandle(runHandle, 1);
        Spf.SpfCiphertextHash output2 = Spf.getOutputHandle(runHandle, 2);

        // Verify each output handle is unique
        assertTrue(Spf.SpfCiphertextHash.unwrap(output0) != Spf.SpfCiphertextHash.unwrap(output1));
        assertTrue(Spf.SpfCiphertextHash.unwrap(output1) != Spf.SpfCiphertextHash.unwrap(output2));
        assertTrue(Spf.SpfCiphertextHash.unwrap(output0) != Spf.SpfCiphertextHash.unwrap(output2));

        // Verify the first output was requested for decryption
        vm.prank(THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(DECRYPTED_VALUE);

        assertTrue(mockUser.decryptionReceived());
    }

    function test_ResetDecryptionState() public {
        // Set decryption state
        vm.prank(THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(DECRYPTED_VALUE);

        assertTrue(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), DECRYPTED_VALUE);

        // Reset state
        mockUser.resetDecryptionState();

        // Verify reset worked
        assertFalse(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), 0);
    }
}
