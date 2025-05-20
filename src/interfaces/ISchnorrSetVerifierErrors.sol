// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @title SchnorrSetVerifier errors
/// @notice Defines errors emitted by SchnorrSetVerifier contract
interface ISchnorrSetVerifierErrors {
    /// @notice thrown when address is not a signer
    /// @param addr address that is not a signer
    error NotSigner(address addr);

    /// @notice reverts in addSigner() when max signers limit is reached
    error MaxSignersReached();

    /// @notice reverts in addSigner() when signer is already added
    /// @param signer signer address
    error SignerAlreadyAdded(address signer);

    /// @notice reverts in publishAnswer() when signature is invalid
    error InvalidSignature();

    /// @notice reverts in publishAnswer() when commitment is invalid
    error InvalidCommitment();

    /// @notice reverts in publishAnswer() when signers are not sorted
    error InvalidSignersOrder();

    /// @notice reverts in verifySignature() when number of signatures is less than min signatures threshold
    /// @param numberSigners number of signatures
    /// @param minSignatureThreshold min signatures threshold
    error NotEnoughSignatures(uint256 numberSigners, uint256 minSignatureThreshold);

    /// @notice reverts in addSigner() when public key is invalid
    error InvalidPublicKey();

    /// @notice reverts in addSigner() when address is zero
    error ZeroAddress();

    /// @notice reverts in setMinSignaturesThreshold() when value is zero
    error ZeroValue();

    /// @notice reverts in onlyOwner() when caller is not owner
    error NotOwner();

    /// @notice reverts in verifySignature() when index is invalid
    error InvalidIndex(uint256 index);
}
