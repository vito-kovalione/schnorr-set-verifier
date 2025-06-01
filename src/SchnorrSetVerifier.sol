// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {LibSchnorr} from "scribe/src/libs/LibSchnorr.sol";
import {LibSecp256k1} from "scribe/src/libs/LibSecp256k1.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";
import {Ownable2Step} from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";

import {ISchnorrSetVerifier} from "./interfaces/ISchnorrSetVerifier.sol";
import {SchnorrSetVerifierLib} from "./libs/SchnorrSetVerifierLib.sol";

contract SchnorrSetVerifier is ISchnorrSetVerifier, Ownable2Step {
    using LibSchnorr for LibSecp256k1.Point;
    using LibSecp256k1 for LibSecp256k1.Point;
    using LibSecp256k1 for LibSecp256k1.JacobianPoint;
    using SchnorrSetVerifierLib for bytes;

    /// @notice Maximum number of allowed signers that can be stored in the signer set.
    /// @dev This ensures the signer array, encoded with `abi.encode(Point[])`, fits within
    ///      the EVM’s 24,576-byte contract size limit when stored using SSTORE2.
    ///
    ///      Each signer uses 64 bytes (two uint256 values: x and y).
    ///      ABI encoding overhead:
    ///        - 32 bytes: dynamic offset
    ///        - 32 bytes: array length
    ///      SSTORE2 adds:
    ///        - 1 byte: STOP opcode prefix (used as read offset)
    ///
    ///      Total layout: 1 + 32 + 32 + 64 * n ≤ 24_576
    ///        => MAX_SIGNERS = floor((24_576 - 65) / 64) = 382
    ///
    ///      Additionally, element 0 is reserved as a dummy placeholder for 1-based indexing,
    ///      so only 381 signer slots are usable in practice.
    uint256 constant MAX_SIGNERS = 382;

    /// @notice Index from which valid signer entries start.
    /// @dev We use 1-based indexing, so index 0 is reserved and unused.
    ///      This helps avoid confusion with default zero values.
    uint256 constant START_INDEX = 1;

    /// @notice mapping of signer addresses to their indexes in the signers array
    mapping(address signer => uint256 index) public signerIndexes;

    /// @notice pointer to signers array stored with SSTORE2, signers[0] is empty cause we use 1-based indexing
    address public pointer;

    /// @notice minimum number of signatures required to verify a signature
    uint256 public minSignaturesThreshold;

    constructor(address initialOwner) Ownable(initialOwner) {
        LibSecp256k1.Point[] memory pubKeys = new LibSecp256k1.Point[](
            START_INDEX
        );
        pointer = SSTORE2.write(abi.encode(pubKeys));
    }

    /// @inheritdoc ISchnorrSetVerifier
    function setMinSignaturesThreshold(
        uint256 newThreshold
    ) external override onlyOwner {
        if (newThreshold == 0) revert ZeroValue();

        minSignaturesThreshold = newThreshold;
        emit LogThresholdUpdated(newThreshold);
    }

    /// @inheritdoc ISchnorrSetVerifier
    function addSigner(
        LibSecp256k1.Point memory signerPubKey
    ) external override onlyOwner {
        if (signerPubKey.isZeroPoint()) revert InvalidPublicKey();
        if (signerPubKey.toAddress() == address(0)) revert ZeroAddress();

        bytes memory pubKeys = SSTORE2.read(pointer); // encoded array of signer pubKeys

        uint256 signersAmount = pubKeys.getSignersLength();
        if (signersAmount == MAX_SIGNERS) revert MaxSignersReached();

        address signer = signerPubKey.toAddress();

        if (signerIndexes[signer] != 0) revert SignerAlreadyAdded(signer);

        signerIndexes[signer] = signersAmount;

        // add signer to array and update length
        pubKeys.addSigner(signerPubKey);

        address newPointer = SSTORE2.write(pubKeys);
        pointer = newPointer;

        emit LogSignerAdded(signer, signersAmount, newPointer);
    }

    /// @inheritdoc ISchnorrSetVerifier
    function removeSigner(address signer) external override onlyOwner {
        uint256 index = signerIndexes[signer];
        if (index == 0) revert NotSigner(signer);

        // encoded array of signer pubKeys
        bytes memory pubKeys = SSTORE2.read(pointer);

        // remove signer from array and update length
        bool orderChanged = pubKeys.removeSigner(index);

        if (orderChanged) {
            address movedSigner = pubKeys.getSigner(index).toAddress();
            signerIndexes[movedSigner] = index;
        }

        address newPointer = SSTORE2.write(pubKeys);
        pointer = newPointer;
        delete signerIndexes[signer];

        emit LogSignerRemoved(signer, index, newPointer);
    }

    /// @inheritdoc ISchnorrSetVerifier
    function verifySignature(
        bytes32 message,
        SchnorrSignature calldata schnorrData
    ) external view {
        if (schnorrData.signature == bytes32(0)) revert InvalidSignature();
        if (schnorrData.signers.length == 0) revert InvalidSignersOrder();
        if (schnorrData.commitment == address(0)) revert InvalidCommitment();

        uint256 numberSigners = schnorrData.signers.length;

        if (numberSigners < minSignaturesThreshold) {
            revert NotEnoughSignatures(numberSigners, minSignaturesThreshold);
        }

        LibSecp256k1.Point[] memory pubKeys = _getPubKeys();
        uint256 signerSetLength = pubKeys.length;
        uint256 firstIndex = schnorrData.signers[0];
        if (firstIndex == 0 || firstIndex >= signerSetLength)
            revert InvalidIndex(firstIndex);
        LibSecp256k1.JacobianPoint memory aggPubKey = pubKeys[
            schnorrData.signers[0]
        ].toJacobian();

        for (uint256 i = START_INDEX; i < numberSigners; i++) {
            uint256 signerIndex = schnorrData.signers[i];

            if (signerIndex == 0 || signerIndex >= signerSetLength)
                revert InvalidIndex(signerIndex);
            if (signerIndex <= schnorrData.signers[i - 1])
                revert InvalidSignersOrder();

            aggPubKey.addAffinePoint(pubKeys[schnorrData.signers[i]]);
        }

        bool isValid = aggPubKey.toAffine().verifySignature(
            message,
            schnorrData.signature,
            schnorrData.commitment
        );
        if (!isValid) revert InvalidSignature();
    }

    /// @inheritdoc ISchnorrSetVerifier
    function isSigner(
        address signer
    ) external view override returns (bool isRegisteredSigner) {
        isRegisteredSigner = signerIndexes[signer] != 0;
    }

    /// @inheritdoc ISchnorrSetVerifier
    function getSigners()
        external
        view
        override
        returns (address[] memory signers)
    {
        LibSecp256k1.Point[] memory pubKeys = _getPubKeys();
        signers = new address[](pubKeys.length - START_INDEX);
        for (uint256 i = 0; i < signers.length; i++) {
            signers[i] = pubKeys[i + START_INDEX].toAddress();
        }
    }

    /// @inheritdoc ISchnorrSetVerifier
    function getSignerIndex(
        address signer
    ) external view override returns (uint256 index) {
        index = signerIndexes[signer];
    }

    /// @inheritdoc ISchnorrSetVerifier
    function getTotalSigners()
        external
        view
        override
        returns (uint256 totalSigners)
    {
        bytes memory pubKeys = SSTORE2.read(pointer);
        totalSigners = pubKeys.getSignersLength() - START_INDEX;
    }

    /// @inheritdoc ISchnorrSetVerifier
    function getSignerSetHash() external view override returns (bytes32 hash) {
        hash = keccak256(SSTORE2.read(pointer));
    }

    function _getPubKeys()
        internal
        view
        returns (LibSecp256k1.Point[] memory pubKeys)
    {
        pubKeys = abi.decode(SSTORE2.read(pointer), (LibSecp256k1.Point[]));
    }
}
