// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/Hpu.sol";

// Create a test contract that exposes the Hpu library functions
contract HpuWrapper {
    using Hpu for *;

    function exposedRequestHpu(
        Hpu.HpuLibrary hpuLibrary,
        Hpu.HpuProgram program,
        Hpu.HpuParameter[] calldata inputs,
        uint256 numOutputs
    ) external returns (Hpu.HpuRunHandle) {
        return Hpu.requestHpu(hpuLibrary, program, inputs, numOutputs);
    }

    function exposedGetOutputHandle(Hpu.HpuRunHandle runHandle, uint8 index) external pure returns (Hpu.HpuParameter) {
        return Hpu.getOutputHandle(runHandle, index);
    }

    // Helper to create a HpuRun struct for comparison in tests
    function createHpuRun(Hpu.HpuLibrary hpuLibrary, Hpu.HpuProgram program, Hpu.HpuParameter[] memory parameters)
        external
        pure
        returns (Hpu.HpuRun memory)
    {
        return Hpu.HpuRun({hpuLibrary: hpuLibrary, program: program, parameters: parameters});
    }
}

contract HpuTest is Test {
    HpuWrapper public hpuWrapper;

    // Event to test against
    event RunProgramOnHpu(address indexed sender, Hpu.HpuRun run);

    function setUp() public {
        hpuWrapper = new HpuWrapper();
    }

    function test_RequestHpu_EmitsEvent() public {
        // Prepare test data
        Hpu.HpuLibrary hpuLibrary = Hpu.HpuLibrary.wrap(bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef)));
        Hpu.HpuProgram program = Hpu.HpuProgram.wrap(bytes32(uint256(0x0000bcdef1234567890abcdef1234567890abcdef12)));

        Hpu.HpuParameter[] memory inputs = new Hpu.HpuParameter[](2);
        inputs[0] = Hpu.HpuParameter.wrap(bytes32(uint256(0x001111111111111111111111111111111111111111)));
        inputs[1] = Hpu.HpuParameter.wrap(bytes32(uint256(0x002222222222222222222222222222222222222222)));

        uint256 numOutputs = 2;

        // Calculate expected extended parameters
        Hpu.HpuParameter[] memory expectedParams = new Hpu.HpuParameter[](4);
        expectedParams[0] = inputs[0];
        expectedParams[1] = inputs[1];
        expectedParams[2] = Hpu.HpuParameter.wrap(bytes32(0));
        expectedParams[3] = Hpu.HpuParameter.wrap(bytes32(0));

        // Create the expected HpuRun struct
        Hpu.HpuRun memory expectedRun = hpuWrapper.createHpuRun(hpuLibrary, program, expectedParams);

        // Expect the RunProgramOnHpu event with correct parameters
        vm.expectEmit(true, true, false, true);
        emit RunProgramOnHpu(address(this), expectedRun);

        // Call the function
        Hpu.HpuRunHandle returnedHandle = hpuWrapper.exposedRequestHpu(hpuLibrary, program, inputs, numOutputs);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash = keccak256(abi.encode(expectedRun));
        assertEq(Hpu.HpuRunHandle.unwrap(returnedHandle), expectedHash);
    }

    function test_RequestHpu_RequireInputs() public {
        // Prepare test data
        Hpu.HpuLibrary hpuLibrary = Hpu.HpuLibrary.wrap(bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef)));
        Hpu.HpuProgram program = Hpu.HpuProgram.wrap(bytes32(uint256(0x0000bcdef1234567890abcdef1234567890abcdef12)));

        Hpu.HpuParameter[] memory inputs = new Hpu.HpuParameter[](0);
        uint256 numOutputs = 2;

        // Expect revert with specific message
        vm.expectRevert("HPU: No inputs provided");
        hpuWrapper.exposedRequestHpu(hpuLibrary, program, inputs, numOutputs);
    }

    function test_RequestHpu_RequireOutputs() public {
        // Prepare test data
        Hpu.HpuLibrary hpuLibrary = Hpu.HpuLibrary.wrap(bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef)));
        Hpu.HpuProgram program = Hpu.HpuProgram.wrap(bytes32(uint256(0x0000bcdef1234567890abcdef1234567890abcdef12)));

        Hpu.HpuParameter[] memory inputs = new Hpu.HpuParameter[](1);
        inputs[0] = Hpu.HpuParameter.wrap(bytes32(uint256(0x001111111111111111111111111111111111111111)));
        uint256 numOutputs = 0;

        // Expect revert with specific message
        vm.expectRevert("HPU: No outputs requested");
        hpuWrapper.exposedRequestHpu(hpuLibrary, program, inputs, numOutputs);
    }

    function test_RequestHpu_ExtendedParameters() public {
        // Prepare test data
        Hpu.HpuLibrary hpuLibrary = Hpu.HpuLibrary.wrap(bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef)));
        Hpu.HpuProgram program = Hpu.HpuProgram.wrap(bytes32(uint256(0x0000bcdef1234567890abcdef1234567890abcdef12)));

        Hpu.HpuParameter[] memory inputs = new Hpu.HpuParameter[](1);
        inputs[0] = Hpu.HpuParameter.wrap(bytes32(uint256(0x001111111111111111111111111111111111111111)));

        uint256 numOutputs = 3;

        // Calculate expected extended parameters
        Hpu.HpuParameter[] memory expectedParams = new Hpu.HpuParameter[](4);
        expectedParams[0] = inputs[0];
        expectedParams[1] = Hpu.HpuParameter.wrap(bytes32(0));
        expectedParams[2] = Hpu.HpuParameter.wrap(bytes32(0));
        expectedParams[3] = Hpu.HpuParameter.wrap(bytes32(0));

        // Create the expected HpuRun struct
        Hpu.HpuRun memory expectedRun = hpuWrapper.createHpuRun(hpuLibrary, program, expectedParams);

        // Expect the RunProgramOnHpu event with correct parameters
        vm.expectEmit(true, true, false, true);
        emit RunProgramOnHpu(address(this), expectedRun);

        // Call the function
        Hpu.HpuRunHandle returnedHandle = hpuWrapper.exposedRequestHpu(hpuLibrary, program, inputs, numOutputs);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash = keccak256(abi.encode(expectedRun));
        assertEq(Hpu.HpuRunHandle.unwrap(returnedHandle), expectedHash);
    }

    function test_GetOutputHandle() public view {
        // Create a test run handle
        bytes32 testRunHash = bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef));
        Hpu.HpuRunHandle runHandle = Hpu.HpuRunHandle.wrap(testRunHash);

        // Test output handles for different indices
        Hpu.HpuParameter output0 = hpuWrapper.exposedGetOutputHandle(runHandle, 0);
        Hpu.HpuParameter output1 = hpuWrapper.exposedGetOutputHandle(runHandle, 1);
        Hpu.HpuParameter output2 = hpuWrapper.exposedGetOutputHandle(runHandle, 2);

        // Verify each output handle is unique
        assertTrue(Hpu.HpuParameter.unwrap(output0) != Hpu.HpuParameter.unwrap(output1));
        assertTrue(Hpu.HpuParameter.unwrap(output1) != Hpu.HpuParameter.unwrap(output2));
        assertTrue(Hpu.HpuParameter.unwrap(output0) != Hpu.HpuParameter.unwrap(output2));

        // Verify deterministic output - same input parameters should result in same output handles
        Hpu.HpuParameter output0Again = hpuWrapper.exposedGetOutputHandle(runHandle, 0);
        assertEq(Hpu.HpuParameter.unwrap(output0), Hpu.HpuParameter.unwrap(output0Again));

        // Verify output handles are correctly derived from the run handle and index
        bytes32 expectedOutput0 = keccak256(abi.encodePacked(runHandle, uint8(0)));
        assertEq(Hpu.HpuParameter.unwrap(output0), expectedOutput0);

        bytes32 expectedOutput1 = keccak256(abi.encodePacked(runHandle, uint8(1)));
        assertEq(Hpu.HpuParameter.unwrap(output1), expectedOutput1);
    }

    function test_GetOutputHandle_DifferentRuns() public view {
        // Create two different run handles
        bytes32 testRunHash1 = bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef));
        bytes32 testRunHash2 = bytes32(uint256(0x0000fedcba0987654321fedcba0987654321fedcba));

        Hpu.HpuRunHandle runHandle1 = Hpu.HpuRunHandle.wrap(testRunHash1);
        Hpu.HpuRunHandle runHandle2 = Hpu.HpuRunHandle.wrap(testRunHash2);

        // Verify output handles are correctly derived from the run handle and index
        bytes32 expectedOutput0 = keccak256(abi.encodePacked(runHandle1, uint8(0)));
        assertEq(Hpu.HpuParameter.unwrap(hpuWrapper.exposedGetOutputHandle(runHandle1, 0)), expectedOutput0);

        bytes32 expectedOutput1 = keccak256(abi.encodePacked(runHandle1, uint8(1)));
        assertEq(Hpu.HpuParameter.unwrap(hpuWrapper.exposedGetOutputHandle(runHandle1, 1)), expectedOutput1);

        bytes32 expectedOutput2 = keccak256(abi.encodePacked(runHandle2, uint8(0)));
        assertEq(Hpu.HpuParameter.unwrap(hpuWrapper.exposedGetOutputHandle(runHandle2, 0)), expectedOutput2);

        bytes32 expectedOutput3 = keccak256(abi.encodePacked(runHandle2, uint8(1)));
        assertEq(Hpu.HpuParameter.unwrap(hpuWrapper.exposedGetOutputHandle(runHandle2, 1)), expectedOutput3);
    }

    function test_outputHash() public pure {
        // Create sample input parameters
        Hpu.HpuParameter[] memory parameters = new Hpu.HpuParameter[](4);
        parameters[0] = Hpu.HpuParameter.wrap(bytes32(uint256(1)));
        parameters[1] = Hpu.HpuParameter.wrap(bytes32(uint256(2)));
        parameters[2] = Hpu.HpuParameter.wrap(bytes32(uint256(3)));
        parameters[3] = Hpu.HpuParameter.wrap(bytes32(uint256(0)));

        // Create HpuRun struct
        Hpu.HpuRun memory run = Hpu.HpuRun({
            hpuLibrary: Hpu.HpuLibrary.wrap(bytes32(uint256(123))),
            program: Hpu.HpuProgram.wrap(bytes32("hello")),
            parameters: parameters
        });

        // Calculate the hash using the library function
        bytes32 calculatedHash = Hpu.outputHash(run);

        bytes memory encoding = abi.encode(run);
        console.logBytes(encoding);

        // Manually calculate the expected hash to compare
        bytes32 expectedHash = keccak256(abi.encode(run));

        // Assert that the function returns the expected hash
        assertEq(calculatedHash, expectedHash, "outputHash returned incorrect hash");
    }

    function test_outputHashWithEmptyParameters() public pure {
        // Create HpuRun struct with empty parameters array
        Hpu.HpuParameter[] memory emptyParams = new Hpu.HpuParameter[](0);

        Hpu.HpuRun memory run = Hpu.HpuRun({
            hpuLibrary: Hpu.HpuLibrary.wrap(bytes32(uint256(999))),
            program: Hpu.HpuProgram.wrap(bytes32(uint256(888))),
            parameters: emptyParams
        });

        // Calculate the hash using the library function
        bytes32 calculatedHash = Hpu.outputHash(run);

        // Manually calculate the expected hash to compare
        bytes32 expectedHash = keccak256(abi.encode(run));

        // Assert that the function returns the expected hash
        assertEq(calculatedHash, expectedHash, "outputHash with empty parameters returned incorrect hash");
    }

    function test_outputHashDifferentInputsDifferentHashes() public pure {
        // Create first HpuRun struct
        Hpu.HpuParameter[] memory params1 = new Hpu.HpuParameter[](1);
        params1[0] = Hpu.HpuParameter.wrap(bytes32(uint256(42)));

        Hpu.HpuRun memory run1 = Hpu.HpuRun({
            hpuLibrary: Hpu.HpuLibrary.wrap(bytes32(uint256(111))),
            program: Hpu.HpuProgram.wrap(bytes32(uint256(222))),
            parameters: params1
        });

        // Create second HpuRun struct with slightly different parameters
        Hpu.HpuParameter[] memory params2 = new Hpu.HpuParameter[](1);
        params2[0] = Hpu.HpuParameter.wrap(bytes32(uint256(43))); // Different value

        Hpu.HpuRun memory run2 = Hpu.HpuRun({
            hpuLibrary: Hpu.HpuLibrary.wrap(bytes32(uint256(111))),
            program: Hpu.HpuProgram.wrap(bytes32(uint256(222))),
            parameters: params2
        });

        // Get hashes for both runs
        bytes32 hash1 = Hpu.outputHash(run1);
        bytes32 hash2 = Hpu.outputHash(run2);

        // Verify that different inputs produce different hashes
        assertTrue(hash1 != hash2, "Different inputs should produce different hashes");
    }

    function test_getOutputHandleMatchesService() public pure {
        Hpu.HpuRunHandle runHash =
            Hpu.HpuRunHandle.wrap(0x7ab8b802b6bcd9051f054bdbdf7b73771f433b8c9822235a3baab8408df372ef);
        assertEq(
            Hpu.HpuParameter.unwrap(Hpu.getOutputHandle(runHash, 2)),
            0xf3ebbcd8d825a5eea4226ff24917bd903549eac69a2e9b2a152eccf026cc3a0e
        );
    }
}
