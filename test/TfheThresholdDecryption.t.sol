// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/TfheThresholdDecryption.sol";
import "./Spf.t.sol";

// Mock contract that inherits from TfheThresholdDecryption
contract MockDecryptionUser is TfheThresholdDecryption {
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
        Spf.SpfParameter memory outputHandle = Spf.getOutputHandle(runHandle, 0);

        // Request threshold decryption of the output
        requestThresholdDecryption(this.handleDecryptionResult.selector, Spf.passToDecryption(outputHandle));

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
        // Deploy the mock user contract
        mockUser = new MockDecryptionUser(TC.SPF_LIBRARY, TC.SPF_PROGRAM);
    }

    function test_ExecuteAndRequestDecryption() public {
        // Create test input parameters
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](3);
        inputs[0] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1);
        inputs[1] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_2);
        inputs[2] = Spf.createOutputCiphertextParameter(32);

        // Expect RunProgramOnSpf event
        vm.expectEmit(true, true, true, true);

        // Calculate expected parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](3);
        expectedParams[0] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[0].payload[0] = Spf.SpfCiphertextIdentifier.unwrap(TC.CIPHERTEXT_ID_1);
        expectedParams[1] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[1].payload[0] = Spf.SpfCiphertextIdentifier.unwrap(TC.CIPHERTEXT_ID_2);
        expectedParams[2] = Spf.SpfParameter({metaData: 0x022001 << 232, payload: new bytes32[](0)});

        // Create expected SpfRun
        Spf.SpfRun memory expectedRun =
            Spf.SpfRun({spfLibrary: mockUser.spfLibrary(), program: mockUser.program(), parameters: expectedParams});

        emit RunProgramOnSpf(address(this), expectedRun);

        // Also expect RequestThresholdDecryption event
        vm.expectEmit(true, true, true, true);

        // Calculate expected output handle
        Spf.SpfRunHandle expectedRunHandle = Spf.SpfRunHandle.wrap(keccak256(abi.encode(expectedRun)));
        Spf.SpfParameter memory expectedOutputHandle = Spf.getOutputHandle(expectedRunHandle, 0);

        emit RequestThresholdDecryption(
            address(this),
            address(mockUser),
            MockDecryptionUser.handleDecryptionResult.selector,
            Spf.SpfCiphertextIdentifier.wrap(expectedOutputHandle.payload[0])
        );

        // Execute the function
        Spf.SpfRunHandle runHandle = mockUser.executeAndRequestDecryption(inputs);

        // Verify returned run handle
        assertEq(Spf.SpfRunHandle.unwrap(runHandle), keccak256(abi.encode(expectedRun)));

        // Verify that no decryption has been received yet
        assertFalse(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), 0);

        vm.prank(TC.THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(TC.DECRYPTED_VALUE);

        // Verify that decryption was received and stored correctly
        assertTrue(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), TC.DECRYPTED_VALUE);
    }

    function test_OnlyThresholdDecryption() public {
        // Try to call the callback function from an unauthorized address
        vm.expectRevert("Only the threshold decryption service can call this function");
        mockUser.handleDecryptionResult(TC.DECRYPTED_VALUE);

        // Verify it works when called from the threshold decryption service
        vm.prank(TC.THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(TC.DECRYPTED_VALUE);

        assertTrue(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), TC.DECRYPTED_VALUE);
    }

    function test_MultipleOutputs() public {
        // Create test input parameters
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](2);
        inputs[0] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1);
        inputs[1] = Spf.createOutputCiphertextArrayParameter(32, 3);

        // Execute the function
        Spf.SpfRunHandle runHandle = mockUser.executeAndRequestDecryption(inputs);

        // Verify we can get all output handles
        Spf.SpfCiphertextIdentifier output0 =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(runHandle, 0).payload[0]);
        Spf.SpfCiphertextIdentifier output1 =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(runHandle, 1).payload[0]);
        Spf.SpfCiphertextIdentifier output2 =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(runHandle, 2).payload[0]);

        // Verify each output handle is unique
        assertTrue(Spf.SpfCiphertextIdentifier.unwrap(output0) != Spf.SpfCiphertextIdentifier.unwrap(output1));
        assertTrue(Spf.SpfCiphertextIdentifier.unwrap(output1) != Spf.SpfCiphertextIdentifier.unwrap(output2));
        assertTrue(Spf.SpfCiphertextIdentifier.unwrap(output0) != Spf.SpfCiphertextIdentifier.unwrap(output2));

        // Verify the first output was requested for decryption
        vm.prank(TC.THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(TC.DECRYPTED_VALUE);

        assertTrue(mockUser.decryptionReceived());
    }

    function test_ResetDecryptionState() public {
        // Set decryption state
        vm.prank(TC.THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(TC.DECRYPTED_VALUE);

        assertTrue(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), TC.DECRYPTED_VALUE);

        // Reset state
        mockUser.resetDecryptionState();

        // Verify reset worked
        assertFalse(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), 0);
    }
}
