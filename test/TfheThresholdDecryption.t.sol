// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/TfheThresholdDecryption.sol";
import "../contracts/Spf.sol";

// Create a test contract that exposes the Spf library functions
contract SpfWrapper {
    using Spf for *;

    function exposedCreateCiphertextParam(bytes32 hash) external pure returns (Spf.SpfParameter memory) {
        return Spf.createCiphertextParam(hash);
    }

    function exposedCreateOutputCiphertextArrayParam(uint8 numBytes) external pure returns (Spf.SpfParameter memory) {
        return Spf.createOutputCiphertextArrayParam(numBytes);
    }
}

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
    function executeAndRequestDecryption(Spf.SpfParameter[] calldata inputs) external returns (Spf.SpfRunHandle) {
        // Run the SPF program
        Spf.SpfRunHandle runHandle = Spf.requestSpf(spfLibrary, program, inputs);

        // Get the zeroth output handle
        Spf.SpfCiphertextIdentifier outputHandle = Spf.getOutputHandle(runHandle, 0);

        // Request threshold decryption of the output
        requestThresholdDecryption(
            this.handleDecryptionResult.selector, Spf.SpfCiphertextIdentifier.unwrap(outputHandle)
        );

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

    // Constants for testing only, no real life meaning
    address constant THRESHOLD_DECRYPTION_SERVICE = 0xB79e28b5DC528DDCa75b2f1Df6d234C2A00Db866;
    uint256 constant DECRYPTED_VALUE = 123;
    Spf.SpfLibrary constant SPF_LIBRARY =
        Spf.SpfLibrary.wrap(0x61dc6dc7d7d82fa0e9870bf697cbb69544fdb1cc0ddac1427fc863b29e129860);
    Spf.SpfProgram constant PROGRAM =
        Spf.SpfProgram.wrap(0x70726F6772616D00000000000000000000000000000000000000000000000000);
    bytes32 constant PARAM_1 = 0x363ec54649521a2aca55a792954a4678698076f38cab85a06bb5de1ef8b20a7c;
    bytes32 constant PARAM_2 = 0x13ca007bae631cf35724b1d4c92ac26cd8fa49c2e1b30cc7b886f86d8a579525;

    SpfWrapper public spfWrapper;

    // Test contract instances
    MockDecryptionUser public mockUser;

    // Events to test against
    event RequestThresholdDecryption(
        address indexed sender,
        address contractAddress,
        bytes4 callbackSelector,
        Spf.SpfCiphertextIdentifier outputHandle
    );

    event RunProgramOnSpf(address indexed sender, Spf.SpfRun run);

    function setUp() public {
        spfWrapper = new SpfWrapper();

        // Deploy the mock user contract
        mockUser = new MockDecryptionUser(SPF_LIBRARY, PROGRAM);
    }

    function test_ExecuteAndRequestDecryption() public {
        // Create test input parameters
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](3);
        inputs[0] = spfWrapper.exposedCreateCiphertextParam(PARAM_1);
        inputs[1] = spfWrapper.exposedCreateCiphertextParam(PARAM_2);
        inputs[2] = spfWrapper.exposedCreateOutputCiphertextArrayParam(4);

        // Expect RunProgramOnSpf event
        vm.expectEmit(true, true, false, true);

        // Calculate expected parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](3);
        expectedParams[0] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[0].payload[0] = PARAM_1;
        expectedParams[1] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[1].payload[0] = PARAM_2;
        expectedParams[2] = Spf.SpfParameter({metaData: 0x0204 << 240, payload: new bytes32[](0)});

        // Create expected SpfRun
        Spf.SpfRun memory expectedRun =
            Spf.SpfRun({spfLibrary: mockUser.spfLibrary(), program: mockUser.program(), parameters: expectedParams});

        emit RunProgramOnSpf(address(this), expectedRun);

        // Also expect RequestThresholdDecryption event
        vm.expectEmit(true, true, true, true);

        // Calculate expected output handle
        Spf.SpfRunHandle expectedRunHandle = Spf.SpfRunHandle.wrap(keccak256(abi.encode(expectedRun)));
        Spf.SpfCiphertextIdentifier expectedOutputHandle = Spf.getOutputHandle(expectedRunHandle, 0);

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
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](2);
        inputs[0] = spfWrapper.exposedCreateCiphertextParam(PARAM_1);
        inputs[1] = spfWrapper.exposedCreateOutputCiphertextArrayParam(12);

        // Execute the function
        Spf.SpfRunHandle runHandle = mockUser.executeAndRequestDecryption(inputs);

        // Verify we can get all output handles
        Spf.SpfCiphertextIdentifier output0 = Spf.getOutputHandle(runHandle, 0);
        Spf.SpfCiphertextIdentifier output1 = Spf.getOutputHandle(runHandle, 1);
        Spf.SpfCiphertextIdentifier output2 = Spf.getOutputHandle(runHandle, 2);

        // Verify each output handle is unique
        assertTrue(Spf.SpfCiphertextIdentifier.unwrap(output0) != Spf.SpfCiphertextIdentifier.unwrap(output1));
        assertTrue(Spf.SpfCiphertextIdentifier.unwrap(output1) != Spf.SpfCiphertextIdentifier.unwrap(output2));
        assertTrue(Spf.SpfCiphertextIdentifier.unwrap(output0) != Spf.SpfCiphertextIdentifier.unwrap(output2));

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
