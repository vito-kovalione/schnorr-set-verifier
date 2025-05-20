// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @title SchnorrSetVerifier Structs Interface
/// @notice Defines structs used by AggreSchnorrSetVerifiergator contract
interface ISchnorrSetVerifierStructs {
    /// @notice Schnorr signature data struct
    /// @dev signers indexes array must be sorted in ascending order
    /// @param signature aggregated signature
    /// @param commitment commitment
    /// @param signers array of signers
    struct SchnorrSignature {
        bytes32 signature;
        address commitment;
        uint256[] signers; 
    }
}
