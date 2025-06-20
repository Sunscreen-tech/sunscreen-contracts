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
    function executeAndRequestDecryption(Spf.SpfParameter[] calldata inputs, uint256 numOutputs)
        external
        returns (Spf.SpfRunHandle)
    {
        // Run the SPF program
        Spf.SpfRunHandle runHandle = Spf.requestSpf(spfLibrary, program, inputs, numOutputs);

        // Get the zeroth output handle
        Spf.SpfParameter outputHandle = Spf.getOutputHandle(runHandle, 0);

        // Request threshold decryption of the output
        requestThresholdDecryption(this.handleDecryptionResult.selector, Spf.SpfParameter.unwrap(outputHandle));

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

    // Test contract instances
    MockDecryptionUser public mockUser;

    // Events to test against
    event RequestThresholdDecryption(
        address indexed sender, address contractAddress, bytes4 callbackSelector, Spf.SpfParameter param
    );

    event RunProgramOnSpf(address indexed sender, Spf.SpfRun run);

    function setUp() public {
        // Create some test SPF library and program identifiers
        Spf.SpfLibrary spfLibrary = Spf.SpfLibrary.wrap(bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef)));
        Spf.SpfProgram program = Spf.SpfProgram.wrap(bytes32(uint256(0x0000bcdef1234567890abcdef1234567890abcdef12)));

        // Deploy the mock user contract
        mockUser = new MockDecryptionUser(spfLibrary, program);
    }

    function test_ExecuteAndRequestDecryption() public {
        // Create test input parameters
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](2);
        inputs[0] = Spf.SpfParameter.wrap(bytes32(uint256(0x001111111111111111111111111111111111111111)));
        inputs[1] = Spf.SpfParameter.wrap(bytes32(uint256(0x002222222222222222222222222222222222222222)));

        uint256 numOutputs = 1;

        // Expect RunProgramOnSpf event
        vm.expectEmit(true, true, false, true);

        // Calculate expected extended parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](3);
        expectedParams[0] = inputs[0];
        expectedParams[1] = inputs[1];
        expectedParams[2] = Spf.SpfParameter.wrap(bytes32(0));

        // Create expected SpfRun
        Spf.SpfRun memory expectedRun =
            Spf.SpfRun({spfLibrary: mockUser.spfLibrary(), program: mockUser.program(), parameters: expectedParams});

        emit RunProgramOnSpf(address(this), expectedRun);

        // Also expect RequestThresholdDecryption event
        vm.expectEmit(true, true, true, true);

        // Calculate expected output handle
        Spf.SpfRunHandle expectedRunHandle = Spf.SpfRunHandle.wrap(keccak256(abi.encode(expectedRun)));
        Spf.SpfParameter expectedOutputHandle = Spf.getOutputHandle(expectedRunHandle, 0);

        emit RequestThresholdDecryption(
            address(this), address(mockUser), MockDecryptionUser.handleDecryptionResult.selector, expectedOutputHandle
        );

        // Execute the function
        Spf.SpfRunHandle runHandle = mockUser.executeAndRequestDecryption(inputs, numOutputs);

        // Verify returned run handle
        assertEq(Spf.SpfRunHandle.unwrap(runHandle), keccak256(abi.encode(expectedRun)));

        // Verify that no decryption has been received yet
        assertFalse(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), 0);

        // Simulate response from the threshold decryption service
        uint256 mockDecryptedValue = 42;

        vm.prank(THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(mockDecryptedValue);

        // Verify that decryption was received and stored correctly
        assertTrue(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), mockDecryptedValue);
    }

    function test_OnlyThresholdDecryption() public {
        // Try to call the callback function from an unauthorized address
        vm.expectRevert("Only the threshold decryption service can call this function");
        mockUser.handleDecryptionResult(123);

        // Verify it works when called from the threshold decryption service
        vm.prank(THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(123);

        assertTrue(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), 123);
    }

    function test_MultipleOutputs() public {
        // Create test input parameters
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](1);
        inputs[0] = Spf.SpfParameter.wrap(bytes32(uint256(0x001111111111111111111111111111111111111111)));

        uint256 numOutputs = 3;

        // Execute the function
        Spf.SpfRunHandle runHandle = mockUser.executeAndRequestDecryption(inputs, numOutputs);

        // Verify we can get all output handles
        Spf.SpfParameter output0 = Spf.getOutputHandle(runHandle, 0);
        Spf.SpfParameter output1 = Spf.getOutputHandle(runHandle, 1);
        Spf.SpfParameter output2 = Spf.getOutputHandle(runHandle, 2);

        // Verify each output handle is unique
        assertTrue(Spf.SpfParameter.unwrap(output0) != Spf.SpfParameter.unwrap(output1));
        assertTrue(Spf.SpfParameter.unwrap(output1) != Spf.SpfParameter.unwrap(output2));
        assertTrue(Spf.SpfParameter.unwrap(output0) != Spf.SpfParameter.unwrap(output2));

        // Verify the first output was requested for decryption
        vm.prank(THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(123);

        assertTrue(mockUser.decryptionReceived());
    }

    function test_ResetDecryptionState() public {
        // Set decryption state
        vm.prank(THRESHOLD_DECRYPTION_SERVICE);
        mockUser.handleDecryptionResult(123);

        assertTrue(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), 123);

        // Reset state
        mockUser.resetDecryptionState();

        // Verify reset worked
        assertFalse(mockUser.decryptionReceived());
        assertEq(mockUser.lastDecryptedValue(), 0);
    }
}
