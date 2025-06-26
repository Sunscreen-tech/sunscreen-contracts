// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/Spf.sol";

// Create a test contract that exposes the Spf library functions
contract SpfWrapper {
    using Spf for *;

    function exposedCreateCiphertextParam(bytes32 hash) external pure returns (Spf.SpfParameter memory) {
        return Spf.createCiphertextParam(hash);
    }

    function exposedCreateCiphertextArrayParam(bytes32[] memory hashes)
        external
        pure
        returns (Spf.SpfParameter memory)
    {
        return Spf.createCiphertextArrayParam(hashes);
    }

    function exposedCreateOutputCiphertextArrayParam(uint8 numBytes) external pure returns (Spf.SpfParameter memory) {
        return Spf.createOutputCiphertextArrayParam(numBytes);
    }

    function exposedCreatePlaintextParam(uint8 bitWidth, uint256 value)
        external
        pure
        returns (Spf.SpfParameter memory)
    {
        return Spf.createPlaintextParam(bitWidth, value);
    }

    function exposedCreatePlaintextArrayParam(uint8 bitWidth, uint256[] memory values)
        external
        pure
        returns (Spf.SpfParameter memory)
    {
        return Spf.createPlaintextArrayParam(bitWidth, values);
    }

    function exposedRequestSpf(Spf.SpfLibrary spfLibrary, Spf.SpfProgram program, Spf.SpfParameter[] calldata inputs)
        external
        returns (Spf.SpfRunHandle)
    {
        return Spf.requestSpf(spfLibrary, program, inputs);
    }

    function exposedGetOutputHandle(Spf.SpfRunHandle runHandle, uint8 index)
        external
        pure
        returns (Spf.SpfCiphertextIdentifier)
    {
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
    // Constants for testing only, no real life meaning
    Spf.SpfLibrary constant SPF_LIBRARY =
        Spf.SpfLibrary.wrap(0x61dc6dc7d7d82fa0e9870bf697cbb69544fdb1cc0ddac1427fc863b29e129860);
    Spf.SpfProgram constant SPF_PROGRAM =
        Spf.SpfProgram.wrap(0x70726f6772616d00000000000000000000000000000000000000000000000000);
    Spf.SpfRunHandle constant SPF_RUN_HANDLE =
        Spf.SpfRunHandle.wrap(0x7ab8b802b6bcd9051f054bdbdf7b73771f433b8c9822235a3baab8408df372ef);
    Spf.SpfRunHandle constant SPF_ALT_RUN_HANDLE =
        Spf.SpfRunHandle.wrap(0x10a6c10e36bfd52b3a8f33b33ffcc4ee2b0842c7bc1c5d3a3f6c5fa74aeee315);
    bytes32 constant PARAM_1 = 0x363ec54649521a2aca55a792954a4678698076f38cab85a06bb5de1ef8b20a7c;
    bytes32 constant PARAM_2 = 0x13ca007bae631cf35724b1d4c92ac26cd8fa49c2e1b30cc7b886f86d8a579525;
    bytes32 constant PARAM_3 = 0x8b797ec858caad3e954b722e257c88e21ce069b7ed28bb8d37dbf5927259e4b8;
    bytes32 constant PARAM_4 = 0xe09312d4fba52955d7aaffe9dcd224f7e69995a8226acb7422130cab2313be07;

    SpfWrapper public spfWrapper;

    // Event to test against
    event RunProgramOnSpf(address indexed sender, Spf.SpfRun run);

    function setUp() public {
        spfWrapper = new SpfWrapper();
    }

    function test_RequestSpf_EmitsEvent() public {
        // Prepare test data
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](3);
        inputs[0] = spfWrapper.exposedCreateCiphertextParam(PARAM_1);
        inputs[1] = spfWrapper.exposedCreateCiphertextParam(PARAM_2);
        inputs[2] = spfWrapper.exposedCreateOutputCiphertextArrayParam(4);

        // Calculate expected parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](3);
        expectedParams[0] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[0].payload[0] = PARAM_1;
        expectedParams[1] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[1].payload[0] = PARAM_2;
        expectedParams[2] = Spf.SpfParameter({metaData: 0x0204 << 240, payload: new bytes32[](0)});

        // Create the expected SpfRun struct
        Spf.SpfRun memory expectedRun = spfWrapper.createSpfRun(SPF_LIBRARY, SPF_PROGRAM, expectedParams);

        // Expect the RunProgramOnSpf event with correct parameters
        vm.expectEmit(true, true, false, true);
        emit RunProgramOnSpf(address(this), expectedRun);

        // Call the function
        Spf.SpfRunHandle returnedHandle = spfWrapper.exposedRequestSpf(SPF_LIBRARY, SPF_PROGRAM, inputs);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash = keccak256(abi.encode(expectedRun));
        assertEq(Spf.SpfRunHandle.unwrap(returnedHandle), expectedHash);
    }

    function test_RequestSpf_RequireInputs() public {
        // Prepare test data
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](0);

        // Expect revert with specific message
        vm.expectRevert("SPF: No inputs provided");
        spfWrapper.exposedRequestSpf(SPF_LIBRARY, SPF_PROGRAM, inputs);
    }

    function test_RequestSpf_RequireOutputs() public {
        // Prepare test data
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](1);
        inputs[0] = spfWrapper.exposedCreateCiphertextParam(PARAM_1);

        // Expect revert with specific message
        vm.expectRevert("SPF: No outputs requested");
        spfWrapper.exposedRequestSpf(SPF_LIBRARY, SPF_PROGRAM, inputs);
    }

    function test_RequestSpf_Parameters() public {
        // Prepare test data
        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = PARAM_2;
        hashes[1] = PARAM_3;
        hashes[2] = PARAM_4;

        uint256[] memory values = new uint256[](3);
        values[0] = 2;
        values[1] = 3;
        values[2] = 4;

        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](5);
        inputs[0] = spfWrapper.exposedCreateCiphertextParam(PARAM_1);
        inputs[1] = spfWrapper.exposedCreateCiphertextArrayParam(hashes);
        inputs[2] = spfWrapper.exposedCreateOutputCiphertextArrayParam(4);
        inputs[3] = spfWrapper.exposedCreatePlaintextParam(32, 1);
        inputs[4] = spfWrapper.exposedCreatePlaintextArrayParam(32, values);

        // Calculate expected parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](5);
        expectedParams[0] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[0].payload[0] = PARAM_1;
        expectedParams[1] = Spf.SpfParameter({metaData: 0x01 << 248, payload: hashes});
        expectedParams[2] = Spf.SpfParameter({metaData: 0x0204 << 240, payload: new bytes32[](0)});
        expectedParams[3] = Spf.SpfParameter({metaData: 0x0320 << 240, payload: new bytes32[](1)});
        expectedParams[3].payload[0] = bytes32(uint256(1));
        expectedParams[4] = Spf.SpfParameter({metaData: 0x0420 << 240, payload: new bytes32[](3)});
        expectedParams[4].payload[0] = bytes32(values[0]);
        expectedParams[4].payload[1] = bytes32(values[1]);
        expectedParams[4].payload[2] = bytes32(values[2]);

        // Create the expected SpfRun struct
        Spf.SpfRun memory expectedRun = spfWrapper.createSpfRun(SPF_LIBRARY, SPF_PROGRAM, expectedParams);

        // Expect the RunProgramOnSpf event with correct parameters
        vm.expectEmit(true, true, false, true);
        emit RunProgramOnSpf(address(this), expectedRun);

        // Call the function
        Spf.SpfRunHandle returnedHandle = spfWrapper.exposedRequestSpf(SPF_LIBRARY, SPF_PROGRAM, inputs);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash = keccak256(abi.encode(expectedRun));
        assertEq(Spf.SpfRunHandle.unwrap(returnedHandle), expectedHash);
    }

    function test_GetOutputHandle() public view {
        // Test output handles for different indices
        Spf.SpfCiphertextIdentifier output0 = spfWrapper.exposedGetOutputHandle(SPF_RUN_HANDLE, 0);
        Spf.SpfCiphertextIdentifier output1 = spfWrapper.exposedGetOutputHandle(SPF_RUN_HANDLE, 1);
        Spf.SpfCiphertextIdentifier output2 = spfWrapper.exposedGetOutputHandle(SPF_RUN_HANDLE, 2);

        // Verify each output handle is unique
        assertNotEq(Spf.SpfCiphertextIdentifier.unwrap(output0), Spf.SpfCiphertextIdentifier.unwrap(output1));
        assertNotEq(Spf.SpfCiphertextIdentifier.unwrap(output1), Spf.SpfCiphertextIdentifier.unwrap(output2));
        assertNotEq(Spf.SpfCiphertextIdentifier.unwrap(output0), Spf.SpfCiphertextIdentifier.unwrap(output2));

        // Verify deterministic output - same input parameters should result in same output handles
        Spf.SpfCiphertextIdentifier output0Again = spfWrapper.exposedGetOutputHandle(SPF_RUN_HANDLE, 0);
        assertEq(Spf.SpfCiphertextIdentifier.unwrap(output0), Spf.SpfCiphertextIdentifier.unwrap(output0Again));

        // Verify output handles are correctly derived from the run handle and index
        bytes32 expectedOutput0 = keccak256(abi.encodePacked(SPF_RUN_HANDLE, uint8(0)));
        assertEq(Spf.SpfCiphertextIdentifier.unwrap(output0), expectedOutput0);

        bytes32 expectedOutput1 = keccak256(abi.encodePacked(SPF_RUN_HANDLE, uint8(1)));
        assertEq(Spf.SpfCiphertextIdentifier.unwrap(output1), expectedOutput1);
    }

    function test_GetOutputHandle_DifferentRuns() public view {
        // Verify output handles are correctly derived from the run handle and index
        bytes32 expectedOutput0 = keccak256(abi.encodePacked(SPF_RUN_HANDLE, uint8(0)));
        assertEq(
            Spf.SpfCiphertextIdentifier.unwrap(spfWrapper.exposedGetOutputHandle(SPF_RUN_HANDLE, 0)), expectedOutput0
        );

        bytes32 expectedOutput1 = keccak256(abi.encodePacked(SPF_RUN_HANDLE, uint8(1)));
        assertEq(
            Spf.SpfCiphertextIdentifier.unwrap(spfWrapper.exposedGetOutputHandle(SPF_RUN_HANDLE, 1)), expectedOutput1
        );

        bytes32 expectedOutput2 = keccak256(abi.encodePacked(SPF_ALT_RUN_HANDLE, uint8(0)));
        assertEq(
            Spf.SpfCiphertextIdentifier.unwrap(spfWrapper.exposedGetOutputHandle(SPF_ALT_RUN_HANDLE, 0)),
            expectedOutput2
        );

        bytes32 expectedOutput3 = keccak256(abi.encodePacked(SPF_ALT_RUN_HANDLE, uint8(1)));
        assertEq(
            Spf.SpfCiphertextIdentifier.unwrap(spfWrapper.exposedGetOutputHandle(SPF_ALT_RUN_HANDLE, 1)),
            expectedOutput3
        );
    }

    function test_outputHash() public view {
        // Create sample input parameters
        Spf.SpfParameter[] memory parameters = new Spf.SpfParameter[](5);
        parameters[0] = spfWrapper.exposedCreateCiphertextParam(PARAM_1);
        parameters[1] = spfWrapper.exposedCreateCiphertextParam(PARAM_2);
        parameters[2] = spfWrapper.exposedCreateCiphertextParam(PARAM_3);
        parameters[3] = spfWrapper.exposedCreateCiphertextParam(PARAM_4);
        parameters[4] = spfWrapper.exposedCreateOutputCiphertextArrayParam(4);

        // Create SpfRun struct
        Spf.SpfRun memory run = Spf.SpfRun({spfLibrary: SPF_LIBRARY, program: SPF_PROGRAM, parameters: parameters});

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

        // This won't be able to actually run due to number of inputs check, just for testing
        Spf.SpfRun memory run = Spf.SpfRun({spfLibrary: SPF_LIBRARY, program: SPF_PROGRAM, parameters: emptyParams});

        // Calculate the hash using the library function
        bytes32 calculatedHash = Spf.outputHash(run);

        // Manually calculate the expected hash to compare
        bytes32 expectedHash = keccak256(abi.encode(run));

        // Assert that the function returns the expected hash
        assertEq(calculatedHash, expectedHash, "outputHash with empty parameters returned incorrect hash");
    }

    function test_outputHashDifferentInputsDifferentHashes() public view {
        // Create first SpfRun struct
        Spf.SpfParameter[] memory params1 = new Spf.SpfParameter[](2);
        params1[0] = spfWrapper.exposedCreateCiphertextParam(PARAM_1);
        params1[1] = spfWrapper.exposedCreateOutputCiphertextArrayParam(4);

        Spf.SpfRun memory run1 = Spf.SpfRun({spfLibrary: SPF_LIBRARY, program: SPF_PROGRAM, parameters: params1});

        // Create second SpfRun struct with slightly different parameters
        Spf.SpfParameter[] memory params2 = new Spf.SpfParameter[](2);
        params2[0] = spfWrapper.exposedCreateCiphertextParam(PARAM_2); // Different value
        params2[1] = spfWrapper.exposedCreateOutputCiphertextArrayParam(4);

        Spf.SpfRun memory run2 = Spf.SpfRun({spfLibrary: SPF_LIBRARY, program: SPF_PROGRAM, parameters: params2});

        // Get hashes for both runs
        bytes32 hash1 = Spf.outputHash(run1);
        bytes32 hash2 = Spf.outputHash(run2);

        // Verify that different inputs produce different hashes
        assertTrue(hash1 != hash2, "Different inputs should produce different hashes");
    }

    function test_getOutputHandleMatchesService() public pure {
        assertEq(
            Spf.SpfCiphertextIdentifier.unwrap(Spf.getOutputHandle(SPF_RUN_HANDLE, 2)),
            0xf3ebbcd8d825a5eea4226ff24917bd903549eac69a2e9b2a152eccf026cc3a0e
        );
    }
}
