// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @title SchnorrSetVerifier events
/// @notice Defines events emitted by SchnorrSetVerifier contract
interface ISchnorrSetVerifierEvents {
    /// @notice emitted when new signer is added
    /// @param signer new signer address
    /// @param index index of the new signer
    /// @param pointer pointer to the signers array
    event LogSignerAdded(address indexed signer, uint256 index, address pointer);

    /// @notice emitted when signer is removed
    /// @param signer removed signer address
    /// @param oldIndex index of the removed signer
    /// @param pointer pointer to the signers array
    event LogSignerRemoved(address indexed signer, uint256 oldIndex, address pointer);

    /// @notice emitted when threshold is updated
    /// @param newThreshold new threshold
    event LogThresholdUpdated(uint256 newThreshold);
}
