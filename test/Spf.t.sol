// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/Spf.sol";

contract SpfTest is Test {
    using Spf for *;

    // Constants for testing only, no real life meaning
    Spf.SpfLibrary constant SPF_LIBRARY =
        Spf.SpfLibrary.wrap(0x61dc6dc7d7d82fa0e9870bf697cbb69544fdb1cc0ddac1427fc863b29e129860);
    Spf.SpfProgram constant SPF_PROGRAM = Spf.SpfProgram.wrap("program");
    Spf.SpfRunHandle constant SPF_RUN_HANDLE =
        Spf.SpfRunHandle.wrap(0x7ab8b802b6bcd9051f054bdbdf7b73771f433b8c9822235a3baab8408df372ef);
    Spf.SpfRunHandle constant SPF_ALT_RUN_HANDLE =
        Spf.SpfRunHandle.wrap(0x10a6c10e36bfd52b3a8f33b33ffcc4ee2b0842c7bc1c5d3a3f6c5fa74aeee315);
    Spf.SpfCiphertextIdentifier constant CIPHERTEXT_ID_1 =
        Spf.SpfCiphertextIdentifier.wrap(0x363ec54649521a2aca55a792954a4678698076f38cab85a06bb5de1ef8b20a7c);
    Spf.SpfCiphertextIdentifier constant CIPHERTEXT_ID_2 =
        Spf.SpfCiphertextIdentifier.wrap(0x13ca007bae631cf35724b1d4c92ac26cd8fa49c2e1b30cc7b886f86d8a579525);
    Spf.SpfCiphertextIdentifier constant CIPHERTEXT_ID_3 =
        Spf.SpfCiphertextIdentifier.wrap(0x8b797ec858caad3e954b722e257c88e21ce069b7ed28bb8d37dbf5927259e4b8);
    Spf.SpfCiphertextIdentifier constant CIPHERTEXT_ID_4 =
        Spf.SpfCiphertextIdentifier.wrap(0xe09312d4fba52955d7aaffe9dcd224f7e69995a8226acb7422130cab2313be07);

    // Event to test against
    event RunProgramOnSpf(address indexed sender, Spf.SpfRun run);

    // Check that our string gets converted into a 32 byte identifier.
    function test_programEncoding() public pure {
        assertEq(Spf.SpfProgram.unwrap(SPF_PROGRAM), 0x70726f6772616d00000000000000000000000000000000000000000000000000);
    }

    function test_RequestSpf_EmitsEvent() public {
        // Prepare test data
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](3);
        inputs[0] = Spf.createCiphertextParameter(CIPHERTEXT_ID_1);
        inputs[1] = Spf.createCiphertextParameter(CIPHERTEXT_ID_2);
        inputs[2] = Spf.createOutputCiphertextParameter(32);

        // Calculate expected parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](3);
        expectedParams[0] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[0].payload[0] = Spf.SpfCiphertextIdentifier.unwrap(CIPHERTEXT_ID_1);
        expectedParams[1] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[1].payload[0] = Spf.SpfCiphertextIdentifier.unwrap(CIPHERTEXT_ID_2);
        expectedParams[2] = Spf.SpfParameter({metaData: 0x022001 << 232, payload: new bytes32[](0)});

        // Create the expected SpfRun struct
        Spf.SpfRun memory expectedRun =
            Spf.SpfRun({spfLibrary: SPF_LIBRARY, program: SPF_PROGRAM, parameters: expectedParams});

        // Expect the RunProgramOnSpf event with correct parameters
        vm.expectEmit(true, true, true, true);
        emit RunProgramOnSpf(msg.sender, expectedRun);

        // Call the function
        Spf.SpfRunHandle returnedHandle = Spf.requestSpf(SPF_LIBRARY, SPF_PROGRAM, inputs);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash = keccak256(abi.encode(expectedRun));
        assertEq(Spf.SpfRunHandle.unwrap(returnedHandle), expectedHash);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_RequestSpf_RequireInputs() public {
        // Prepare test data
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](0);

        // Expect revert with specific message
        vm.expectRevert("SPF: No inputs provided");
        Spf.requestSpf(SPF_LIBRARY, SPF_PROGRAM, inputs);
    }

    // These reverts are expected to be internal, so we allow them in the test configuration
    // See https://getfoundry.sh/misc/v1.0-migration/#expect-revert-cheatcode-disabled-on-internal-calls-by-default
    /// forge-config: default.allow_internal_expect_revert = true
    function test_RequestSpf_RequireOutputs() public {
        // Prepare test data
        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](1);
        inputs[0] = Spf.createCiphertextParameter(CIPHERTEXT_ID_1);

        // Expect revert with specific message
        vm.expectRevert("SPF: No outputs requested");
        Spf.requestSpf(SPF_LIBRARY, SPF_PROGRAM, inputs);
    }

    function test_RequestSpf_Parameters() public {
        // Prepare test data
        Spf.SpfCiphertextIdentifier[] memory identifiers = new Spf.SpfCiphertextIdentifier[](3);
        identifiers[0] = CIPHERTEXT_ID_2;
        identifiers[1] = CIPHERTEXT_ID_3;
        identifiers[2] = CIPHERTEXT_ID_4;

        uint256[] memory values = new uint256[](3);
        values[0] = 2;
        values[1] = 3;
        values[2] = 4;

        Spf.SpfParameter[] memory inputs = new Spf.SpfParameter[](6);
        inputs[0] = Spf.createCiphertextParameter(CIPHERTEXT_ID_1);
        inputs[1] = Spf.createCiphertextArrayParameter(identifiers);
        inputs[2] = Spf.createOutputCiphertextParameter(32);
        inputs[3] = Spf.createOutputCiphertextArrayParameter(32, 4);
        inputs[4] = Spf.createPlaintextParameter(32, 1);
        inputs[5] = Spf.createPlaintextArrayParameter(32, values);

        // Calculate expected parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](6);
        expectedParams[0] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[0].payload[0] = Spf.SpfCiphertextIdentifier.unwrap(CIPHERTEXT_ID_1);
        expectedParams[1] = Spf.SpfParameter({metaData: 0x01 << 248, payload: new bytes32[](3)});
        expectedParams[1].payload[0] = Spf.SpfCiphertextIdentifier.unwrap(identifiers[0]);
        expectedParams[1].payload[1] = Spf.SpfCiphertextIdentifier.unwrap(identifiers[1]);
        expectedParams[1].payload[2] = Spf.SpfCiphertextIdentifier.unwrap(identifiers[2]);
        expectedParams[2] = Spf.SpfParameter({metaData: 0x022001 << 232, payload: new bytes32[](0)});
        expectedParams[3] = Spf.SpfParameter({metaData: 0x022004 << 232, payload: new bytes32[](0)});
        expectedParams[4] = Spf.SpfParameter({metaData: 0x0320 << 240, payload: new bytes32[](1)});
        expectedParams[4].payload[0] = bytes32(uint256(1));
        expectedParams[5] = Spf.SpfParameter({metaData: 0x0420 << 240, payload: new bytes32[](3)});
        expectedParams[5].payload[0] = bytes32(values[0]);
        expectedParams[5].payload[1] = bytes32(values[1]);
        expectedParams[5].payload[2] = bytes32(values[2]);

        // create the expected SpfRun struct
        Spf.SpfRun memory expectedRun =
            Spf.SpfRun({spfLibrary: SPF_LIBRARY, program: SPF_PROGRAM, parameters: expectedParams});

        // Expect the RunProgramOnSpf event with correct parameters
        vm.expectEmit(true, true, true, true);
        emit RunProgramOnSpf(msg.sender, expectedRun);

        // Call the function
        Spf.SpfRunHandle returnedHandle = Spf.requestSpf(SPF_LIBRARY, SPF_PROGRAM, inputs);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash = keccak256(abi.encode(expectedRun));
        assertEq(Spf.SpfRunHandle.unwrap(returnedHandle), expectedHash);
    }

    function test_GetOutputHandle() public pure {
        // Test output handles for different indices
        Spf.SpfCiphertextIdentifier output0 =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(SPF_RUN_HANDLE, 0).payload[0]);
        Spf.SpfCiphertextIdentifier output1 =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(SPF_RUN_HANDLE, 1).payload[0]);
        Spf.SpfCiphertextIdentifier output2 =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(SPF_RUN_HANDLE, 2).payload[0]);

        // Verify each output handle is unique
        assertNotEq(Spf.SpfCiphertextIdentifier.unwrap(output0), Spf.SpfCiphertextIdentifier.unwrap(output1));
        assertNotEq(Spf.SpfCiphertextIdentifier.unwrap(output1), Spf.SpfCiphertextIdentifier.unwrap(output2));
        assertNotEq(Spf.SpfCiphertextIdentifier.unwrap(output0), Spf.SpfCiphertextIdentifier.unwrap(output2));

        // Verify deterministic output - same input parameters should result in same output handles
        Spf.SpfCiphertextIdentifier output0Again =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(SPF_RUN_HANDLE, 0).payload[0]);
        assertEq(Spf.SpfCiphertextIdentifier.unwrap(output0), Spf.SpfCiphertextIdentifier.unwrap(output0Again));

        // Verify output handles are correctly derived from the run handle and index
        bytes32 expectedOutput0 = keccak256(abi.encodePacked(SPF_RUN_HANDLE, uint8(0)));
        assertEq(Spf.SpfCiphertextIdentifier.unwrap(output0), expectedOutput0);

        bytes32 expectedOutput1 = keccak256(abi.encodePacked(SPF_RUN_HANDLE, uint8(1)));
        assertEq(Spf.SpfCiphertextIdentifier.unwrap(output1), expectedOutput1);
    }

    function test_GetOutputHandle_DifferentRuns() public pure {
        // Verify output handles are correctly derived from the run handle and index
        bytes32 expectedOutput0 = keccak256(abi.encodePacked(SPF_RUN_HANDLE, uint8(0)));
        assertEq(Spf.getOutputHandle(SPF_RUN_HANDLE, 0).payload[0], expectedOutput0);

        bytes32 expectedOutput1 = keccak256(abi.encodePacked(SPF_RUN_HANDLE, uint8(1)));
        assertEq(Spf.getOutputHandle(SPF_RUN_HANDLE, 1).payload[0], expectedOutput1);

        bytes32 expectedOutput2 = keccak256(abi.encodePacked(SPF_ALT_RUN_HANDLE, uint8(0)));
        assertEq(Spf.getOutputHandle(SPF_ALT_RUN_HANDLE, 0).payload[0], expectedOutput2);

        bytes32 expectedOutput3 = keccak256(abi.encodePacked(SPF_ALT_RUN_HANDLE, uint8(1)));
        assertEq(Spf.getOutputHandle(SPF_ALT_RUN_HANDLE, 1).payload[0], expectedOutput3);
    }

    function test_outputHash() public pure {
        // create sample input parameters
        Spf.SpfParameter[] memory parameters = new Spf.SpfParameter[](5);
        parameters[0] = Spf.createCiphertextParameter(CIPHERTEXT_ID_1);
        parameters[1] = Spf.createCiphertextParameter(CIPHERTEXT_ID_2);
        parameters[2] = Spf.createCiphertextParameter(CIPHERTEXT_ID_3);
        parameters[3] = Spf.createCiphertextParameter(CIPHERTEXT_ID_4);
        parameters[4] = Spf.createOutputCiphertextParameter(32);

        // create SpfRun struct
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

    function test_outputHashDifferentInputsDifferentHashes() public pure {
        // create first SpfRun struct
        Spf.SpfParameter[] memory params1 = new Spf.SpfParameter[](2);
        params1[0] = Spf.createCiphertextParameter(CIPHERTEXT_ID_1);
        params1[1] = Spf.createOutputCiphertextParameter(32);

        Spf.SpfRun memory run1 = Spf.SpfRun({spfLibrary: SPF_LIBRARY, program: SPF_PROGRAM, parameters: params1});

        // create second SpfRun struct with slightly different parameters
        Spf.SpfParameter[] memory params2 = new Spf.SpfParameter[](2);
        params2[0] = Spf.createCiphertextParameter(CIPHERTEXT_ID_2); // Different value
        params2[1] = Spf.createOutputCiphertextParameter(32);

        Spf.SpfRun memory run2 = Spf.SpfRun({spfLibrary: SPF_LIBRARY, program: SPF_PROGRAM, parameters: params2});

        // Get hashes for both runs
        bytes32 hash1 = Spf.outputHash(run1);
        bytes32 hash2 = Spf.outputHash(run2);

        // Verify that different inputs produce different hashes
        assertTrue(hash1 != hash2, "Different inputs should produce different hashes");
    }

    function test_getOutputHandleMatchesService() public pure {
        assertEq(
            Spf.getOutputHandle(SPF_RUN_HANDLE, 2).payload[0],
            0xf3ebbcd8d825a5eea4226ff24917bd903549eac69a2e9b2a152eccf026cc3a0e
        );
    }
}
