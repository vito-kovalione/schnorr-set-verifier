// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {LibSecp256k1} from "scribe/src/libs/LibSecp256k1.sol";

/// @title SchnorrSetVerifier interface
/// @notice Interface for a smart contract that verifies Schnorr signatures from a set of authorized signers
/// @dev This contract manages a set of signers and verifies aggregated Schnorr signatures
interface ISchnorrSetVerifier {
    /// @notice Schnorr signature data struct containing aggregated signature information
    /// @dev signers indexes array must be sorted in ascending order to prevent replay attacks
    /// @param signature The aggregated Schnorr signature
    /// @param commitment The commitment point used in the signature
    /// @param signers Array of signer indices that participated in the signature
    struct SchnorrSignature {
        bytes32 signature;
        address commitment;
        uint256[] signers; 
    }

    /// @notice Thrown when an address is not a registered signer
    /// @param addr The address that is not a signer
    error NotSigner(address addr);

    /// @notice Thrown when attempting to add a signer but the maximum number of signers has been reached
    error MaxSignersReached();

    /// @notice Thrown when attempting to add a signer that is already registered
    /// @param signer The address of the signer that is already registered
    error SignerAlreadyAdded(address signer);

    /// @notice Thrown when the provided signature fails verification
    error InvalidSignature();

    /// @notice Thrown when the provided commitment point is invalid
    error InvalidCommitment();

    /// @notice Thrown when the signers array is not sorted in ascending order
    error InvalidSignersOrder();

    /// @notice Thrown when the number of signatures is less than the minimum required threshold
    /// @param numberSigners The number of signatures provided
    /// @param minSignatureThreshold The minimum number of signatures required
    error NotEnoughSignatures(uint256 numberSigners, uint256 minSignatureThreshold);

    /// @notice Thrown when the provided public key is invalid
    error InvalidPublicKey();

    /// @notice Thrown when attempting to add a signer with a zero address
    error ZeroAddress();

    /// @notice Thrown when attempting to set a zero value for the minimum signatures threshold
    error ZeroValue();

    /// @notice Thrown when a signer index is invalid (zero or out of bounds)
    /// @param index The invalid index
    error InvalidIndex(uint256 index);

    /// @notice Emitted when a new signer is added to the set
    /// @param signer The address of the new signer
    /// @param index The index assigned to the new signer
    /// @param pointer The storage pointer to the updated signers array
    event LogSignerAdded(address indexed signer, uint256 index, address pointer);

    /// @notice Emitted when a signer is removed from the set
    /// @param signer The address of the removed signer
    /// @param oldIndex The previous index of the removed signer
    /// @param pointer The storage pointer to the updated signers array
    event LogSignerRemoved(address indexed signer, uint256 oldIndex, address pointer);

    /// @notice Emitted when the minimum signatures threshold is updated
    /// @param newThreshold The new minimum number of signatures required
    event LogThresholdUpdated(uint256 newThreshold);

    /// @notice Adds a new signer to the verifier set
    /// @dev The signer's public key must be valid and not already registered
    /// @param signer The public key of the new signer
    function addSigner(LibSecp256k1.Point memory signer) external;

    /// @notice Removes a signer from the verifier set
    /// @dev The signer must exist in the set
    /// @param signer The address of the signer to remove
    function removeSigner(address signer) external;

    /// @notice Verifies a Schnorr signature against a message
    /// @dev The signature must be valid and meet the minimum threshold requirement
    /// @param message The message that was signed
    /// @param schnorrData The Schnorr signature data containing the signature, commitment, and signers
    function verifySignature(bytes32 message, SchnorrSignature calldata schnorrData) external view;

    /// @notice Sets the minimum number of signatures required for verification
    /// @dev The new threshold must be greater than zero
    /// @param newThreshold The new minimum number of signatures required
    function setMinSignaturesThreshold(uint256 newThreshold) external;

    /// @notice Returns the total number of registered signers
    /// @return The number of signers in the set
    function getTotalSigners() external view returns (uint256);

    /// @notice Returns the list of all registered signer addresses
    /// @return An array of signer addresses
    function getSigners() external view returns (address[] memory);

    /// @notice Returns the index of a signer in the set
    /// @param signer The address of the signer to look up
    /// @return The index of the signer, or 0 if not found
    function getSignerIndex(address signer) external view returns (uint256);

    /// @notice Checks if an address is a registered signer
    /// @param signer The address to check
    /// @return True if the address is a registered signer, false otherwise
    function isSigner(address signer) external view returns (bool);

    /// @notice Returns the hash of the current signer set
    /// @return The keccak256 hash of the signer set
    function getSignerSetHash() external view returns (bytes32);
}
