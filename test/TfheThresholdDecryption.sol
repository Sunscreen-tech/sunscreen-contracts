// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/TfheThresholdDecryption.sol";
import "../contracts/Hpu.sol";

// Mock contract that inherits from TfheThresholdDecryption
contract MockDecryptionUser is TfheThresholdDecryption {
    using Hpu for *;

    // Store decryption results for verification
    uint256 public lastDecryptedValue;
    bool public decryptionReceived;

    // Library and program to use for HPU
    Hpu.HpuLibrary public hpuLibrary;
    Hpu.HpuProgram public program;

    constructor(Hpu.HpuLibrary _hpuLibrary, Hpu.HpuProgram _program) {
        hpuLibrary = _hpuLibrary;
        program = _program;
    }

    // Function to execute an HPU program and request decryption of its output
    function executeAndRequestDecryption(Hpu.HpuParameter[] calldata inputs, uint256 numOutputs)
        external
        returns (Hpu.HpuRunHandle)
    {
        // Run the HPU program
        Hpu.HpuRunHandle runHandle = Hpu.requestHpu(hpuLibrary, program, inputs, numOutputs);

        // Get the zeroth output handle
        Hpu.HpuParameter outputHandle = Hpu.getOutputHandle(runHandle, 0);

        // Request threshold decryption of the output
        requestThresholdDecryption(this.handleDecryptionResult.selector, Hpu.HpuParameter.unwrap(outputHandle));

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
    using Hpu for *;

    // Constants for testing
    address constant THRESHOLD_DECRYPTION_SERVICE = 0xB79e28b5DC528DDCa75b2f1Df6d234C2A00Db866;

    // Test contract instances
    MockDecryptionUser public mockUser;

    // Events to test against
    event RequestThresholdDecryption(
        address indexed sender, address contractAddress, bytes4 callbackSelector, Hpu.HpuParameter param
    );

    event RunProgramOnHpu(address indexed sender, Hpu.HpuRun run);

    function setUp() public {
        // Create some test HPU library and program identifiers
        Hpu.HpuLibrary hpuLibrary = Hpu.HpuLibrary.wrap(bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef)));
        Hpu.HpuProgram program = Hpu.HpuProgram.wrap(bytes32(uint256(0x0000bcdef1234567890abcdef1234567890abcdef12)));

        // Deploy the mock user contract
        mockUser = new MockDecryptionUser(hpuLibrary, program);
    }

    function test_ExecuteAndRequestDecryption() public {
        // Create test input parameters
        Hpu.HpuParameter[] memory inputs = new Hpu.HpuParameter[](2);
        inputs[0] = Hpu.HpuParameter.wrap(bytes32(uint256(0x001111111111111111111111111111111111111111)));
        inputs[1] = Hpu.HpuParameter.wrap(bytes32(uint256(0x002222222222222222222222222222222222222222)));

        uint256 numOutputs = 1;

        // Expect RunProgramOnHpu event
        vm.expectEmit(true, true, false, true);

        // Calculate expected extended parameters
        Hpu.HpuParameter[] memory expectedParams = new Hpu.HpuParameter[](3);
        expectedParams[0] = inputs[0];
        expectedParams[1] = inputs[1];
        expectedParams[2] = Hpu.HpuParameter.wrap(bytes32(0));

        // Create expected HpuRun
        Hpu.HpuRun memory expectedRun =
            Hpu.HpuRun({hpuLibrary: mockUser.hpuLibrary(), program: mockUser.program(), parameters: expectedParams});

        emit RunProgramOnHpu(address(this), expectedRun);

        // Also expect RequestThresholdDecryption event
        vm.expectEmit(true, true, true, true);

        // Calculate expected output handle
        Hpu.HpuRunHandle expectedRunHandle = Hpu.HpuRunHandle.wrap(keccak256(abi.encode(expectedRun)));
        Hpu.HpuParameter expectedOutputHandle = Hpu.getOutputHandle(expectedRunHandle, 0);

        emit RequestThresholdDecryption(
            address(this), address(mockUser), MockDecryptionUser.handleDecryptionResult.selector, expectedOutputHandle
        );

        // Execute the function
        Hpu.HpuRunHandle runHandle = mockUser.executeAndRequestDecryption(inputs, numOutputs);

        // Verify returned run handle
        assertEq(Hpu.HpuRunHandle.unwrap(runHandle), keccak256(abi.encode(expectedRun)));

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
        Hpu.HpuParameter[] memory inputs = new Hpu.HpuParameter[](1);
        inputs[0] = Hpu.HpuParameter.wrap(bytes32(uint256(0x001111111111111111111111111111111111111111)));

        uint256 numOutputs = 3;

        // Execute the function
        Hpu.HpuRunHandle runHandle = mockUser.executeAndRequestDecryption(inputs, numOutputs);

        // Verify we can get all output handles
        Hpu.HpuParameter output0 = Hpu.getOutputHandle(runHandle, 0);
        Hpu.HpuParameter output1 = Hpu.getOutputHandle(runHandle, 1);
        Hpu.HpuParameter output2 = Hpu.getOutputHandle(runHandle, 2);

        // Verify each output handle is unique
        assertTrue(Hpu.HpuParameter.unwrap(output0) != Hpu.HpuParameter.unwrap(output1));
        assertTrue(Hpu.HpuParameter.unwrap(output1) != Hpu.HpuParameter.unwrap(output2));
        assertTrue(Hpu.HpuParameter.unwrap(output0) != Hpu.HpuParameter.unwrap(output2));

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
