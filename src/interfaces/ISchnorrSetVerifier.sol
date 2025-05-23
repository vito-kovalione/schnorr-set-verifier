// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {ISchnorrSetVerifierStructs} from "./ISchnorrSetVerifierStructs.sol";
import {ISchnorrSetVerifierEvents} from "./ISchnorrSetVerifierEvents.sol";
import {ISchnorrSetVerifierErrors} from "./ISchnorrSetVerifierErrors.sol";

import {LibSecp256k1} from "../libs/LibSecp256k1.sol";

/// @title SchnorrSetVerifier interface
/// @notice Interface for schnorr set verifier smart contract
interface ISchnorrSetVerifier is ISchnorrSetVerifierStructs, ISchnorrSetVerifierEvents, ISchnorrSetVerifierErrors {
    /// @notice Adds new signer to the verifier.
    /// @param signer signer public key
    function addSigner(LibSecp256k1.Point memory signer) external;

    /// @notice Removes signer from the verifier.
    /// @param signer signer address
    function removeSigner(address signer) external;

    /// @notice Verifies schnorr signature
    /// @param message message
    /// @param schnorrData schnorr signature data
    function verifySignature(bytes32 message, SchnorrSignature calldata schnorrData) external view;

    /// @notice Sets minimum number of signatures required to successfully verify signature
    /// @param newThreshold new threshold
    function setMinSignaturesThreshold(uint256 newThreshold) external;

    /// @notice Returns number of signers
    /// @return number of signers
    function getTotalSigners() external view returns (uint256);

    /// @notice Returns list of signers
    /// @return signers array of signers
    function getSigners() external view returns (address[] memory);

    /// @notice Returns signer index in the list of pubkeys
    /// @param signer signer address
    /// @return index signer index
    function getSignerIndex(address signer) external view returns (uint256);

    /// @notice Returns if address is a signer
    /// @param signer signer address
    /// @return true if address is a signer
    function isSigner(address signer) external view returns (bool);

    /// @notice Returns hash of the signer set
    /// @return hash of the signer set
    function getSignerSetHash() external view returns (bytes32);
}
