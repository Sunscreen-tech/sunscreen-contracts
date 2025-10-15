// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/Spf.sol";

// Library for "test constants" that have no real life meaning
library TC {
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

    address constant ADDRESS_1 = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    address constant ADDRESS_2 = 0x90F79bf6EB2c4f870365E785982E1f101E93b906;

    address constant ADDRESS_3 = 0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc;

    address constant THRESHOLD_DECRYPTION_SERVICE = 0xB79e28b5DC528DDCa75b2f1Df6d234C2A00Db866;

    uint256 constant DECRYPTED_VALUE = 123;
}

contract SpfTest is Test {
    // Event to test against
    event RunProgramOnSpf(address indexed sender, Spf.SpfRun run);

    event ChangeAccessOnSpf(address indexed sender, Spf.SpfAccess access);

    // Check that our string gets converted into a 32 byte identifier.
    function test_programEncoding() public pure {
        assertEq(
            Spf.SpfProgram.unwrap(TC.SPF_PROGRAM), 0x70726f6772616d00000000000000000000000000000000000000000000000000
        );
    }

    function test_RequestRun_EmitsEvent() public {
        // Prepare test data
        Spf.SpfParameter[] memory params = new Spf.SpfParameter[](3);
        params[0] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1);
        params[1] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_2);
        params[2] = Spf.createOutputCiphertextParameter(32);

        // Calculate expected parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](3);
        expectedParams[0] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[0].payload[0] = Spf.SpfCiphertextIdentifier.unwrap(TC.CIPHERTEXT_ID_1);
        expectedParams[1] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[1].payload[0] = Spf.SpfCiphertextIdentifier.unwrap(TC.CIPHERTEXT_ID_2);
        expectedParams[2] = Spf.SpfParameter({metaData: 0x022001 << 232, payload: new bytes32[](0)});

        // Create the expected SpfRun struct
        Spf.SpfRun memory expectedRun =
            Spf.SpfRun({spfLibrary: TC.SPF_LIBRARY, program: TC.SPF_PROGRAM, parameters: expectedParams});

        // Expect the RunProgramOnSpf event with correct parameters
        vm.expectEmit(true, true, true, true);
        emit RunProgramOnSpf(address(this), expectedRun);

        // Call the function
        Spf.SpfRunHandle returnedHandle = Spf.requestRunAsContract(TC.SPF_LIBRARY, TC.SPF_PROGRAM, params);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash =
            keccak256(bytes.concat(abi.encode(expectedRun), bytes8(uint64(block.chainid)), bytes20(address(this))));
        assertEq(Spf.SpfRunHandle.unwrap(returnedHandle), expectedHash);
    }

    function test_RequestRun_RequesterAffectingRunHandle() public {
        // Prepare test data
        Spf.SpfParameter[] memory params = new Spf.SpfParameter[](3);
        params[0] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1);
        params[1] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_2);
        params[2] = Spf.createOutputCiphertextParameter(32);

        Spf.SpfRunHandle msgSenderRunHandle = Spf.requestRunAsSender(TC.SPF_LIBRARY, TC.SPF_PROGRAM, params);
        Spf.SpfRunHandle addrThisRunHandle = Spf.requestRunAsContract(TC.SPF_LIBRARY, TC.SPF_PROGRAM, params);

        assertNotEq(Spf.SpfRunHandle.unwrap(msgSenderRunHandle), Spf.SpfRunHandle.unwrap(addrThisRunHandle));
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_RequestRun_RequireParams() public {
        // Prepare test data
        Spf.SpfParameter[] memory params = new Spf.SpfParameter[](0);

        // Expect revert with specific message
        vm.expectRevert("SPF: No parameters provided");
        Spf.requestRunAsSender(TC.SPF_LIBRARY, TC.SPF_PROGRAM, params);
    }

    // These reverts are expected to be internal, so we allow them in the test configuration
    // See https://getfoundry.sh/misc/v1.0-migration/#expect-revert-cheatcode-disabled-on-internal-calls-by-default
    /// forge-config: default.allow_internal_expect_revert = true
    function test_RequestRun_RequireOutputs() public {
        // Prepare test data
        Spf.SpfParameter[] memory params = new Spf.SpfParameter[](1);
        params[0] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1);

        // Expect revert with specific message
        vm.expectRevert("SPF: No outputs requested");
        Spf.requestRunAsSender(TC.SPF_LIBRARY, TC.SPF_PROGRAM, params);
    }

    function test_RequestRun_Parameters() public {
        // Prepare test data
        Spf.SpfCiphertextIdentifier[] memory identifiers = new Spf.SpfCiphertextIdentifier[](3);
        identifiers[0] = TC.CIPHERTEXT_ID_2;
        identifiers[1] = TC.CIPHERTEXT_ID_3;
        identifiers[2] = TC.CIPHERTEXT_ID_4;

        int128[] memory values = new int128[](3);
        values[0] = 2;
        values[1] = -3;
        values[2] = 4;

        Spf.SpfParameter[] memory params = new Spf.SpfParameter[](6);
        params[0] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1);
        params[1] = Spf.createCiphertextArrayParameter(identifiers);
        params[2] = Spf.createOutputCiphertextParameter(32);
        params[3] = Spf.createOutputCiphertextArrayParameter(32, 4);
        params[4] = Spf.createPlaintextParameter(32, 1);
        params[5] = Spf.createPlaintextArrayParameter(32, values);

        // Calculate expected parameters
        Spf.SpfParameter[] memory expectedParams = new Spf.SpfParameter[](6);
        expectedParams[0] = Spf.SpfParameter({metaData: 0, payload: new bytes32[](1)});
        expectedParams[0].payload[0] = Spf.SpfCiphertextIdentifier.unwrap(TC.CIPHERTEXT_ID_1);
        expectedParams[1] = Spf.SpfParameter({metaData: 0x01 << 248, payload: new bytes32[](3)});
        expectedParams[1].payload[0] = Spf.SpfCiphertextIdentifier.unwrap(identifiers[0]);
        expectedParams[1].payload[1] = Spf.SpfCiphertextIdentifier.unwrap(identifiers[1]);
        expectedParams[1].payload[2] = Spf.SpfCiphertextIdentifier.unwrap(identifiers[2]);
        expectedParams[2] = Spf.SpfParameter({metaData: 0x022001 << 232, payload: new bytes32[](0)});
        expectedParams[3] = Spf.SpfParameter({metaData: 0x022004 << 232, payload: new bytes32[](0)});
        expectedParams[4] = Spf.SpfParameter({metaData: 0x0320 << 240, payload: new bytes32[](1)});
        expectedParams[4].payload[0] = bytes32(uint256(1));
        expectedParams[5] = Spf.SpfParameter({metaData: 0x0420 << 240, payload: new bytes32[](3)});
        expectedParams[5].payload[0] = bytes32(uint256(uint128(values[0])));
        expectedParams[5].payload[1] = bytes32(uint256(uint128(values[1])));
        expectedParams[5].payload[2] = bytes32(uint256(uint128(values[2])));

        // create the expected SpfRun struct
        Spf.SpfRun memory expectedRun =
            Spf.SpfRun({spfLibrary: TC.SPF_LIBRARY, program: TC.SPF_PROGRAM, parameters: expectedParams});

        // Expect the RunProgramOnSpf event with correct parameters
        vm.expectEmit(true, true, true, true);
        emit RunProgramOnSpf(address(this), expectedRun);

        // Call the function
        Spf.SpfRunHandle returnedHandle = Spf.requestRunAsContract(TC.SPF_LIBRARY, TC.SPF_PROGRAM, params);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash =
            keccak256(bytes.concat(abi.encode(expectedRun), bytes8(uint64(block.chainid)), bytes20(address(this))));
        assertEq(Spf.SpfRunHandle.unwrap(returnedHandle), expectedHash);
    }

    function test_GetOutputHandle() public pure {
        // Test output handles for different indices
        Spf.SpfCiphertextIdentifier output0 =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(TC.SPF_RUN_HANDLE, 0).payload[0]);
        Spf.SpfCiphertextIdentifier output1 =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(TC.SPF_RUN_HANDLE, 1).payload[0]);
        Spf.SpfCiphertextIdentifier output2 =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(TC.SPF_RUN_HANDLE, 2).payload[0]);

        // Verify each output handle is unique
        assertNotEq(Spf.SpfCiphertextIdentifier.unwrap(output0), Spf.SpfCiphertextIdentifier.unwrap(output1));
        assertNotEq(Spf.SpfCiphertextIdentifier.unwrap(output1), Spf.SpfCiphertextIdentifier.unwrap(output2));
        assertNotEq(Spf.SpfCiphertextIdentifier.unwrap(output0), Spf.SpfCiphertextIdentifier.unwrap(output2));

        // Verify deterministic output - same input parameters should result in same output handles
        Spf.SpfCiphertextIdentifier output0Again =
            Spf.SpfCiphertextIdentifier.wrap(Spf.getOutputHandle(TC.SPF_RUN_HANDLE, 0).payload[0]);
        assertEq(Spf.SpfCiphertextIdentifier.unwrap(output0), Spf.SpfCiphertextIdentifier.unwrap(output0Again));

        // Verify output handles are correctly derived from the run handle and index
        bytes32 expectedOutput0 = keccak256(abi.encodePacked(TC.SPF_RUN_HANDLE, uint8(0)));
        assertEq(Spf.SpfCiphertextIdentifier.unwrap(output0), expectedOutput0);

        bytes32 expectedOutput1 = keccak256(abi.encodePacked(TC.SPF_RUN_HANDLE, uint8(1)));
        assertEq(Spf.SpfCiphertextIdentifier.unwrap(output1), expectedOutput1);
    }

    function test_GetOutputHandle_DifferentRuns() public pure {
        // Verify output handles are correctly derived from the run handle and index
        bytes32 expectedOutput0 = keccak256(abi.encodePacked(TC.SPF_RUN_HANDLE, uint8(0)));
        assertEq(Spf.getOutputHandle(TC.SPF_RUN_HANDLE, 0).payload[0], expectedOutput0);

        bytes32 expectedOutput1 = keccak256(abi.encodePacked(TC.SPF_RUN_HANDLE, uint8(1)));
        assertEq(Spf.getOutputHandle(TC.SPF_RUN_HANDLE, 1).payload[0], expectedOutput1);

        bytes32 expectedOutput2 = keccak256(abi.encodePacked(TC.SPF_ALT_RUN_HANDLE, uint8(0)));
        assertEq(Spf.getOutputHandle(TC.SPF_ALT_RUN_HANDLE, 0).payload[0], expectedOutput2);

        bytes32 expectedOutput3 = keccak256(abi.encodePacked(TC.SPF_ALT_RUN_HANDLE, uint8(1)));
        assertEq(Spf.getOutputHandle(TC.SPF_ALT_RUN_HANDLE, 1).payload[0], expectedOutput3);
    }

    function test_getRunHandle() public view {
        // create sample input parameters
        Spf.SpfParameter[] memory parameters = new Spf.SpfParameter[](5);
        parameters[0] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1);
        parameters[1] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_2);
        parameters[2] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_3);
        parameters[3] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_4);
        parameters[4] = Spf.createOutputCiphertextParameter(32);

        // create SpfRun struct
        Spf.SpfRun memory run =
            Spf.SpfRun({spfLibrary: TC.SPF_LIBRARY, program: TC.SPF_PROGRAM, parameters: parameters});

        // Calculate the hash using the library function
        bytes32 calculatedHash = Spf.SpfRunHandle.unwrap(Spf.getRunHandleAsContract(run));
        bytes32 anotherCalculatedHash = Spf.SpfRunHandle.unwrap(Spf.getRunHandleWithContractRunner(run, address(this)));
        assertEq(calculatedHash, anotherCalculatedHash, "getRunHandleWithContractRunner returned incorrect hash");

        bytes memory encoding = abi.encode(run);
        console.logBytes(encoding);
        bytes8 chainId = bytes8(uint64(block.chainid));
        console.logBytes8(chainId);
        bytes20 addr = bytes20(address(this));
        console.logBytes20(addr);

        // Manually calculate the expected hash to compare
        bytes32 expectedHash = keccak256(bytes.concat(abi.encode(run), chainId, addr));

        // Assert that the function returns the expected hash
        assertEq(calculatedHash, expectedHash, "getRunHandle returned incorrect hash");
    }

    function test_getRunHandleWithEmptyParameters() public view {
        // Create SpfRun struct with empty parameters array
        Spf.SpfParameter[] memory emptyParams = new Spf.SpfParameter[](0);

        // This won't be able to actually run due to number of parameters check, just for testing
        Spf.SpfRun memory run =
            Spf.SpfRun({spfLibrary: TC.SPF_LIBRARY, program: TC.SPF_PROGRAM, parameters: emptyParams});

        // Calculate the hash using the library function
        bytes32 calculatedHash = Spf.SpfRunHandle.unwrap(Spf.getRunHandleAsContract(run));

        // Manually calculate the expected hash to compare
        bytes32 expectedHash =
            keccak256(bytes.concat(abi.encode(run), bytes8(uint64(block.chainid)), bytes20(address(this))));

        // Assert that the function returns the expected hash
        assertEq(calculatedHash, expectedHash, "runHandle with empty parameters returned incorrect hash");
    }

    function test_getRunHandleDifferentParamsDifferentHashes() public view {
        // create first SpfRun struct
        Spf.SpfParameter[] memory params1 = new Spf.SpfParameter[](2);
        params1[0] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1);
        params1[1] = Spf.createOutputCiphertextParameter(32);

        Spf.SpfRun memory run1 = Spf.SpfRun({spfLibrary: TC.SPF_LIBRARY, program: TC.SPF_PROGRAM, parameters: params1});

        // create second SpfRun struct with slightly different parameters
        Spf.SpfParameter[] memory params2 = new Spf.SpfParameter[](2);
        params2[0] = Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_2); // Different value
        params2[1] = Spf.createOutputCiphertextParameter(32);

        Spf.SpfRun memory run2 = Spf.SpfRun({spfLibrary: TC.SPF_LIBRARY, program: TC.SPF_PROGRAM, parameters: params2});

        // Get hashes for both runs
        bytes32 hash1 = Spf.SpfRunHandle.unwrap(Spf.getRunHandleAsContract(run1));
        bytes32 hash2 = Spf.SpfRunHandle.unwrap(Spf.getRunHandleAsContract(run2));

        // Verify that different parameters produce different hashes
        assertTrue(hash1 != hash2, "Different parameters should produce different hashes");
    }

    function test_getOutputHandleMatchesService() public pure {
        assertEq(
            Spf.getOutputHandle(TC.SPF_RUN_HANDLE, 2).payload[0],
            0xf3ebbcd8d825a5eea4226ff24917bd903549eac69a2e9b2a152eccf026cc3a0e
        );
    }

    function test_RequestAcl_EmitsEvent_And_Parameters() public {
        // Prepare test data
        Spf.SpfAccessChange[] memory changes = new Spf.SpfAccessChange[](6);
        changes[0] = Spf.addCrossChainContractAsAdmin(1, TC.ADDRESS_1);
        changes[1] = Spf.addSignerAsAdmin(TC.ADDRESS_1);
        changes[2] = Spf.allowCrossChainContractRun(1, TC.ADDRESS_2, TC.SPF_LIBRARY, TC.SPF_PROGRAM);
        changes[3] = Spf.allowSignerRun(TC.ADDRESS_2, TC.SPF_LIBRARY, TC.SPF_PROGRAM);
        changes[4] = Spf.allowCrossChainContractDecrypt(1, TC.ADDRESS_3);
        changes[5] = Spf.allowSignerDecrypt(TC.ADDRESS_3);

        // Calculate expected parameters
        Spf.SpfAccessChange[] memory expectedChanges = new Spf.SpfAccessChange[](6);
        expectedChanges[0] = Spf.SpfAccessChange({metaData: 0x00000000000000000001 << 176, payload: new bytes32[](1)});
        expectedChanges[0].payload[0] = bytes32(bytes20(TC.ADDRESS_1));
        expectedChanges[1] = Spf.SpfAccessChange({metaData: 0x0001 << 240, payload: new bytes32[](1)});
        expectedChanges[1].payload[0] = bytes32(bytes20(TC.ADDRESS_1));
        expectedChanges[2] = Spf.SpfAccessChange({metaData: 0x01000000000000000001 << 176, payload: new bytes32[](3)});
        expectedChanges[2].payload[0] = bytes20(TC.ADDRESS_2);
        expectedChanges[2].payload[1] = Spf.SpfLibrary.unwrap(TC.SPF_LIBRARY);
        expectedChanges[2].payload[2] = Spf.SpfProgram.unwrap(TC.SPF_PROGRAM);
        expectedChanges[3] = Spf.SpfAccessChange({metaData: 0x0101 << 240, payload: new bytes32[](3)});
        expectedChanges[3].payload[0] = bytes20(TC.ADDRESS_2);
        expectedChanges[3].payload[1] = Spf.SpfLibrary.unwrap(TC.SPF_LIBRARY);
        expectedChanges[3].payload[2] = Spf.SpfProgram.unwrap(TC.SPF_PROGRAM);
        expectedChanges[4] = Spf.SpfAccessChange({metaData: 0x02000000000000000001 << 176, payload: new bytes32[](1)});
        expectedChanges[4].payload[0] = bytes20(TC.ADDRESS_3);
        expectedChanges[5] = Spf.SpfAccessChange({metaData: 0x0201 << 240, payload: new bytes32[](1)});
        expectedChanges[5].payload[0] = bytes20(TC.ADDRESS_3);

        // Create the expected SpfRun struct
        Spf.SpfAccess memory expectedAccess = Spf.SpfAccess({ciphertext: TC.CIPHERTEXT_ID_1, changes: expectedChanges});

        // Expect the RunProgramOnSpf event with correct parameters
        vm.expectEmit(true, true, true, true);
        emit ChangeAccessOnSpf(msg.sender, expectedAccess);

        // Call the function
        Spf.SpfParameter memory returnedHandle =
            Spf.requestAclAsSender(Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1), changes);

        // Verify the returned handle matches what we expect
        bytes32 expectedHash = keccak256(abi.encode(expectedAccess));
        assertEq(returnedHandle.payload[0], expectedHash);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_RequestAcl_RequireInputs() public {
        // Prepare test data
        Spf.SpfAccessChange[] memory changes = new Spf.SpfAccessChange[](0);

        // Expect revert with specific message
        vm.expectRevert("SPF: No changes specified");
        Spf.requestAclAsSender(Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1), changes);
    }

    function test_RequestAcl_RequesterNotAffectingCiphertextId() public {
        // Prepare test data
        Spf.SpfAccessChange[] memory changes = new Spf.SpfAccessChange[](6);
        changes[0] = Spf.addContractAsAdmin(TC.ADDRESS_1);

        Spf.SpfParameter memory msgSenderParameter =
            Spf.requestAclAsSender(Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1), changes);
        Spf.SpfParameter memory addrThisParameter =
            Spf.requestAclAsContract(Spf.createCiphertextParameter(TC.CIPHERTEXT_ID_1), changes);

        assertEq(msgSenderParameter.payload[0], addrThisParameter.payload[0]);
    }

    function test_outputCiphertextIdentifierDifferentInputsDifferentChanges() public view {
        // create first SpfAccess struct
        Spf.SpfAccessChange[] memory changes1 = new Spf.SpfAccessChange[](2);
        changes1[0] = Spf.allowContractRun(TC.ADDRESS_1, TC.SPF_LIBRARY, TC.SPF_PROGRAM);
        changes1[1] = Spf.allowContractDecrypt(TC.ADDRESS_2);

        Spf.SpfAccess memory access1 = Spf.SpfAccess({ciphertext: TC.CIPHERTEXT_ID_1, changes: changes1});

        // create second SpfAccess struct with slightly different parameters
        Spf.SpfAccessChange[] memory changes2 = new Spf.SpfAccessChange[](2);
        changes2[0] = Spf.allowContractRun(TC.ADDRESS_1, TC.SPF_LIBRARY, TC.SPF_PROGRAM);
        changes2[1] = Spf.allowContractDecrypt(TC.ADDRESS_3); // different value

        Spf.SpfAccess memory access2 = Spf.SpfAccess({ciphertext: TC.CIPHERTEXT_ID_1, changes: changes2});

        // Get hashes for both changes
        bytes32 hash1 = keccak256(abi.encode(access1));
        bytes32 hash2 = keccak256(abi.encode(access2));

        // Verify that different changes produce different hashes
        assertTrue(hash1 != hash2, "Different changes should produce different hashes");
    }
}
