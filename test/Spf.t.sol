// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/Spf.sol";

// Create a test contract that exposes the Spf library functions
contract SpfWrapper {
    using Spf for *;

    function exposedRequestSpf(
        Spf.SpfLibrary spfLibrary,
        Spf.SpfProgram program,
        Spf.SpfParameter[] calldata inputs,
        uint256 numOutputs
    ) external returns (Spf.SpfRunHandle) {
        return Spf.requestSpf(spfLibrary, program, inputs, numOutputs);
    }

    function exposedGetOutputHandle(Spf.SpfRunHandle runHandle, uint8 index) external pure returns (Spf.SpfParameter) {
        return Spf.getOutputHandle(runHandle, index);
    }

    // Helper to create a SpfRun struct for comparison in tests
    function createSpfRun(Spf.SpfLibrary spfLibrary, Spf.SpfProgram program, Spf.SpfParameter[] memory parameters)
        external
        pure
        returns (Spf.SpfRun memory)
    {
        return Spf.SpfRun({spfLibrary: spfLibrary, program: program, parameters: parameters});
    }
}

contract SpfTest is Test {
    SpfWrapper public spfWrapper;

    // Event to test against
    event RunProgramOnSpf(address indexed sender, Spf.SpfRun run);

    function setUp() public {
        spfWrapper = new SpfWrapper();
    }

    function test_RequestSpf_EmitsEvent() public {
        // Prepare test data
        Spf.SpfLibrary spfLibrary = Spf.SpfLibrary.wrap(bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef)));
        Spf.SpfProgram program = Spf.SpfProgram.wrap(bytes32(uint256(0x0000bcdef1234567890abcdef1234567890abcdef12)));

        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](2);
        inputs[0] = Spf.SpfParameter.wrap(bytes32(uint256(0x001111111111111111111111111111111111111111)));
        inputs[1] = Spf.SpfParameter.wrap(bytes32(uint256(0x002222222222222222222222222222222222222222)));

        uint256 numOutputs = 2;

        // Calculate expected extended parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](4);
        expectedParams[0] = inputs[0];
        expectedParams[1] = inputs[1];
        expectedParams[2] = Spf.SpfParameter.wrap(bytes32(0));
        expectedParams[3] = Spf.SpfParameter.wrap(bytes32(0));

        // Create the expected SpfRun struct
        Spf.SpfRun memory expectedRun = spfWrapper.createSpfRun(spfLibrary, program, expectedParams);

        // Expect the RunProgramOnSpf event with correct parameters
        vm.expectEmit(true, true, false, true);
        emit RunProgramOnSpf(address(this), expectedRun);

        // Call the function
        Spf.SpfRunHandle returnedHandle = spfWrapper.exposedRequestSpf(spfLibrary, program, inputs, numOutputs);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash = keccak256(abi.encode(expectedRun));
        assertEq(Spf.SpfRunHandle.unwrap(returnedHandle), expectedHash);
    }

    function test_RequestSpf_RequireInputs() public {
        // Prepare test data
        Spf.SpfLibrary spfLibrary = Spf.SpfLibrary.wrap(bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef)));
        Spf.SpfProgram program = Spf.SpfProgram.wrap(bytes32(uint256(0x0000bcdef1234567890abcdef1234567890abcdef12)));

        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](0);
        uint256 numOutputs = 2;

        // Expect revert with specific message
        vm.expectRevert("SPF: No inputs provided");
        spfWrapper.exposedRequestSpf(spfLibrary, program, inputs, numOutputs);
    }

    function test_RequestSpf_RequireOutputs() public {
        // Prepare test data
        Spf.SpfLibrary spfLibrary = Spf.SpfLibrary.wrap(bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef)));
        Spf.SpfProgram program = Spf.SpfProgram.wrap(bytes32(uint256(0x0000bcdef1234567890abcdef1234567890abcdef12)));

        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](1);
        inputs[0] = Spf.SpfParameter.wrap(bytes32(uint256(0x001111111111111111111111111111111111111111)));
        uint256 numOutputs = 0;

        // Expect revert with specific message
        vm.expectRevert("SPF: No outputs requested");
        spfWrapper.exposedRequestSpf(spfLibrary, program, inputs, numOutputs);
    }

    function test_RequestSpf_ExtendedParameters() public {
        // Prepare test data
        Spf.SpfLibrary spfLibrary = Spf.SpfLibrary.wrap(bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef)));
        Spf.SpfProgram program = Spf.SpfProgram.wrap(bytes32(uint256(0x0000bcdef1234567890abcdef1234567890abcdef12)));

        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](1);
        inputs[0] = Spf.SpfParameter.wrap(bytes32(uint256(0x001111111111111111111111111111111111111111)));

        uint256 numOutputs = 3;

        // Calculate expected extended parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](4);
        expectedParams[0] = inputs[0];
        expectedParams[1] = Spf.SpfParameter.wrap(bytes32(0));
        expectedParams[2] = Spf.SpfParameter.wrap(bytes32(0));
        expectedParams[3] = Spf.SpfParameter.wrap(bytes32(0));

        // Create the expected SpfRun struct
        Spf.SpfRun memory expectedRun = spfWrapper.createSpfRun(spfLibrary, program, expectedParams);

        // Expect the RunProgramOnSpf event with correct parameters
        vm.expectEmit(true, true, false, true);
        emit RunProgramOnSpf(address(this), expectedRun);

        // Call the function
        Spf.SpfRunHandle returnedHandle = spfWrapper.exposedRequestSpf(spfLibrary, program, inputs, numOutputs);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash = keccak256(abi.encode(expectedRun));
        assertEq(Spf.SpfRunHandle.unwrap(returnedHandle), expectedHash);
    }

    function test_GetOutputHandle() public view {
        // Create a test run handle
        bytes32 testRunHash = bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef));
        Spf.SpfRunHandle runHandle = Spf.SpfRunHandle.wrap(testRunHash);

        // Test output handles for different indices
        Spf.SpfParameter output0 = spfWrapper.exposedGetOutputHandle(runHandle, 0);
        Spf.SpfParameter output1 = spfWrapper.exposedGetOutputHandle(runHandle, 1);
        Spf.SpfParameter output2 = spfWrapper.exposedGetOutputHandle(runHandle, 2);

        // Verify each output handle is unique
        assertTrue(Spf.SpfParameter.unwrap(output0) != Spf.SpfParameter.unwrap(output1));
        assertTrue(Spf.SpfParameter.unwrap(output1) != Spf.SpfParameter.unwrap(output2));
        assertTrue(Spf.SpfParameter.unwrap(output0) != Spf.SpfParameter.unwrap(output2));

        // Verify deterministic output - same input parameters should result in same output handles
        Spf.SpfParameter output0Again = spfWrapper.exposedGetOutputHandle(runHandle, 0);
        assertEq(Spf.SpfParameter.unwrap(output0), Spf.SpfParameter.unwrap(output0Again));

        // Verify output handles are correctly derived from the run handle and index
        bytes32 expectedOutput0 = keccak256(abi.encodePacked(runHandle, uint8(0)));
        assertEq(Spf.SpfParameter.unwrap(output0), expectedOutput0);

        bytes32 expectedOutput1 = keccak256(abi.encodePacked(runHandle, uint8(1)));
        assertEq(Spf.SpfParameter.unwrap(output1), expectedOutput1);
    }

    function test_GetOutputHandle_DifferentRuns() public view {
        // Create two different run handles
        bytes32 testRunHash1 = bytes32(uint256(0x0000abcdef1234567890abcdef1234567890abcdef));
        bytes32 testRunHash2 = bytes32(uint256(0x0000fedcba0987654321fedcba0987654321fedcba));

        Spf.SpfRunHandle runHandle1 = Spf.SpfRunHandle.wrap(testRunHash1);
        Spf.SpfRunHandle runHandle2 = Spf.SpfRunHandle.wrap(testRunHash2);

        // Verify output handles are correctly derived from the run handle and index
        bytes32 expectedOutput0 = keccak256(abi.encodePacked(runHandle1, uint8(0)));
        assertEq(Spf.SpfParameter.unwrap(spfWrapper.exposedGetOutputHandle(runHandle1, 0)), expectedOutput0);

        bytes32 expectedOutput1 = keccak256(abi.encodePacked(runHandle1, uint8(1)));
        assertEq(Spf.SpfParameter.unwrap(spfWrapper.exposedGetOutputHandle(runHandle1, 1)), expectedOutput1);

        bytes32 expectedOutput2 = keccak256(abi.encodePacked(runHandle2, uint8(0)));
        assertEq(Spf.SpfParameter.unwrap(spfWrapper.exposedGetOutputHandle(runHandle2, 0)), expectedOutput2);

        bytes32 expectedOutput3 = keccak256(abi.encodePacked(runHandle2, uint8(1)));
        assertEq(Spf.SpfParameter.unwrap(spfWrapper.exposedGetOutputHandle(runHandle2, 1)), expectedOutput3);
    }

    function test_outputHash() public pure {
        // Create sample input parameters
        Spf.SpfParameter[] memory parameters = new Spf.SpfParameter[](4);
        parameters[0] = Spf.SpfParameter.wrap(bytes32(uint256(1)));
        parameters[1] = Spf.SpfParameter.wrap(bytes32(uint256(2)));
        parameters[2] = Spf.SpfParameter.wrap(bytes32(uint256(3)));
        parameters[3] = Spf.SpfParameter.wrap(bytes32(uint256(0)));

        // Create SpfRun struct
        Spf.SpfRun memory run = Spf.SpfRun({
            spfLibrary: Spf.SpfLibrary.wrap(bytes32(uint256(123))),
            program: Spf.SpfProgram.wrap(bytes32("hello")),
            parameters: parameters
        });

        // Calculate the hash using the library function
        bytes32 calculatedHash = Spf.outputHash(run);

        bytes memory encoding = abi.encode(run);
        console.logBytes(encoding);

        // Manually calculate the expected hash to compare
        bytes32 expectedHash = keccak256(abi.encode(run));

        // Assert that the function returns the expected hash
        assertEq(calculatedHash, expectedHash, "outputHash returned incorrect hash");
    }

    function test_outputHashWithEmptyParameters() public pure {
        // Create SpfRun struct with empty parameters array
        Spf.SpfParameter[] memory emptyParams = new Spf.SpfParameter[](0);

        Spf.SpfRun memory run = Spf.SpfRun({
            spfLibrary: Spf.SpfLibrary.wrap(bytes32(uint256(999))),
            program: Spf.SpfProgram.wrap(bytes32(uint256(888))),
            parameters: emptyParams
        });

        // Calculate the hash using the library function
        bytes32 calculatedHash = Spf.outputHash(run);

        // Manually calculate the expected hash to compare
        bytes32 expectedHash = keccak256(abi.encode(run));

        // Assert that the function returns the expected hash
        assertEq(calculatedHash, expectedHash, "outputHash with empty parameters returned incorrect hash");
    }

    function test_outputHashDifferentInputsDifferentHashes() public pure {
        // Create first SpfRun struct
        Spf.SpfParameter[] memory params1 = new Spf.SpfParameter[](1);
        params1[0] = Spf.SpfParameter.wrap(bytes32(uint256(42)));

        Spf.SpfRun memory run1 = Spf.SpfRun({
            spfLibrary: Spf.SpfLibrary.wrap(bytes32(uint256(111))),
            program: Spf.SpfProgram.wrap(bytes32(uint256(222))),
            parameters: params1
        });

        // Create second SpfRun struct with slightly different parameters
        Spf.SpfParameter[] memory params2 = new Spf.SpfParameter[](1);
        params2[0] = Spf.SpfParameter.wrap(bytes32(uint256(43))); // Different value

        Spf.SpfRun memory run2 = Spf.SpfRun({
            spfLibrary: Spf.SpfLibrary.wrap(bytes32(uint256(111))),
            program: Spf.SpfProgram.wrap(bytes32(uint256(222))),
            parameters: params2
        });

        // Get hashes for both runs
        bytes32 hash1 = Spf.outputHash(run1);
        bytes32 hash2 = Spf.outputHash(run2);

        // Verify that different inputs produce different hashes
        assertTrue(hash1 != hash2, "Different inputs should produce different hashes");
    }

    function test_getOutputHandleMatchesService() public pure {
        Spf.SpfRunHandle runHash =
            Spf.SpfRunHandle.wrap(0x7ab8b802b6bcd9051f054bdbdf7b73771f433b8c9822235a3baab8408df372ef);
        assertEq(
            Spf.SpfParameter.unwrap(Spf.getOutputHandle(runHash, 2)),
            0xf3ebbcd8d825a5eea4226ff24917bd903549eac69a2e9b2a152eccf026cc3a0e
        );
    }
}
