// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ISpfSingleProgram
/// @notice Interface for contracts that reference a single SPF program
/// @dev Contracts implementing this interface can be queried for their program metadata,
///      which is used by the SPF client to automatically configure access control rules.
interface ISpfSingleProgram {
    /// @notice Returns the name of the SPF program this contract uses
    /// @dev Program name is ASCII-encoded in bytes32 format
    /// @return The program name as a bytes32 value
    function getProgramName() external view returns (bytes32);

    /// @notice Returns the hash of the SPF library this contract uses
    /// @dev Library hash is the identifier returned when uploading a program to SPF
    /// @return The library hash as a bytes32 value
    function getLibraryHash() external view returns (bytes32);
}
