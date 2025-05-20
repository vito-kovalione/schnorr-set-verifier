// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {LibSchnorr} from "./libs/LibSchnorr.sol";
import {LibSecp256k1} from "./libs/LibSecp256k1.sol";
import {SSTORE2} from "./libs/SSTORE2.sol";

import {ISchnorrSetVerifier} from "./interfaces/ISchnorrSetVerifier.sol";

contract SchnorrSetVerifier is ISchnorrSetVerifier {
    using LibSchnorr for LibSecp256k1.Point;
    using LibSecp256k1 for LibSecp256k1.Point;
    using LibSecp256k1 for LibSecp256k1.JacobianPoint;

    uint256 constant MAX_SIGNERS = 379;

    // pointer to signers array stored with SSTORE2, signers[0] is empty cause we use 1-based indexing
    mapping(address => uint256) internal _signerIndexes; // address => index in signers array
    address internal _owner;

    address public pointer;
    uint256 public minSignaturesThreshold; 

    constructor() {
        _owner = msg.sender;
        LibSecp256k1.Point[] memory pubKeys = new LibSecp256k1.Point[](1);
        pubKeys[0] = LibSecp256k1.ZERO_POINT();  // 0 index is empty, we use 1-based indexing
        pointer = SSTORE2.write(abi.encode(pubKeys));
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) revert NotOwner();
        _;
    }

    /// @inheritdoc ISchnorrSetVerifier
    function setMinSignaturesThreshold(uint256 newThreshold) external override onlyOwner {
        if (newThreshold == 0) revert ZeroValue();

        minSignaturesThreshold = newThreshold;
        emit LogThresholdUpdated(newThreshold);
    }

    /// @inheritdoc ISchnorrSetVerifier
    function addSigner(LibSecp256k1.Point memory signerPubKey) external override onlyOwner {
        if (signerPubKey.isZeroPoint()) revert InvalidPublicKey();
        if (signerPubKey.toAddress() == address(0)) revert ZeroAddress();
       
        bytes memory pubKeys = SSTORE2.read(pointer);  // encoded array of signer pubKeys

        uint256 signersAmount;
        assembly {
            signersAmount := mload(add(pubKeys, 0x40)) // load array length
        }
        if (signersAmount == MAX_SIGNERS) revert MaxSignersReached();

        address signer = signerPubKey.toAddress();

        if (_signerIndexes[signer] != 0) revert SignerAlreadyAdded(signer);

        _signerIndexes[signer] = signersAmount;

        // add signer to array and update length
        assembly {
            let newLength := add(signersAmount, 1)
            let newBlocksLength := mul(newLength, 2)
            let lengthBlock := add(pubKeys, 0x40)
            let newItemBlock1 := sub(add(lengthBlock, mul(newBlocksLength, 0x20)), 0x20)
          
            // resize
            mstore(0x40, add(mload(0x40), 0x40)) // update free memory pointer
            mstore(pubKeys, add(mload(pubKeys), 0x40)) // increase bytes length
            mstore(lengthBlock, newLength) // increase array length

            // write new item
            mstore(newItemBlock1, mload(signerPubKey))
            mstore(add(newItemBlock1, 0x20), mload(add(signerPubKey, 0x20)))
        }

        address newPointer = SSTORE2.write(pubKeys);
        pointer = newPointer;

        emit LogSignerAdded(signer, signersAmount, newPointer);
    }

    /// @inheritdoc ISchnorrSetVerifier
    function removeSigner(address signer) external override onlyOwner {
        uint256 index = _signerIndexes[signer];
        if (index == 0) revert NotSigner(signer);

        // encoded array of signer pubKeys
        bytes memory pubKeys = SSTORE2.read(pointer);
        bool lastSigner = false;
        
        // remove signer from array and update length
         assembly {
            let length := sub(mload(add(pubKeys, 0x40)), 1)
            let lengthBlock := add(pubKeys, 0x40)

            lastSigner := eq(index, length)

            // resize
            mstore(pubKeys, sub(mload(pubKeys), 0x40)) // decrease bytes length
            mstore(lengthBlock, length) // decrease array length

            // move last element to the index of removed element if it's not the last element
            if not(lastSigner) {
                let indexBlock1 := add(add(lengthBlock, mul(index, 0x40)), 0x20)
                let lastItemBlock1 := add(add(lengthBlock, mul(length, 0x40)), 0x20)

                mstore(indexBlock1, mload(lastItemBlock1))
                mstore(add(indexBlock1, 0x20), mload(add(lastItemBlock1, 0x20)))
            }
        }

        if (!lastSigner) {
            // Update _signerIndexes for moved signer
            uint256 x;
            uint256 y;
            assembly {
                x := mload(add(pubKeys, add(0x60, mul(index, 0x40))))
                y := mload(add(pubKeys, add(0x80, mul(index, 0x40))))
            }
            address movedSigner = LibSecp256k1.Point(x, y).toAddress();
            _signerIndexes[movedSigner] = index;
        }

        address newPointer = SSTORE2.write(pubKeys);
        pointer = newPointer;
        delete _signerIndexes[signer];

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
        if (firstIndex == 0 || firstIndex >= signerSetLength) revert InvalidIndex(firstIndex);
        LibSecp256k1.JacobianPoint memory aggPubKey = pubKeys[schnorrData.signers[0]].toJacobian();

        for (uint256 i = 1; i < numberSigners; i++) {
            uint256 signerIndex = schnorrData.signers[i];
            
            if (signerIndex == 0 || signerIndex >= signerSetLength) revert InvalidIndex(signerIndex);
            if (signerIndex <= schnorrData.signers[i - 1]) revert InvalidSignersOrder();
            
            aggPubKey.addAffinePoint(pubKeys[schnorrData.signers[i]]);
        }

        bool isValid = aggPubKey.toAffine().verifySignature(message, schnorrData.signature, schnorrData.commitment);
        if (!isValid) revert InvalidSignature();
    }

    /// @inheritdoc ISchnorrSetVerifier
    function isSigner(address signer) external view override returns (bool) {
        return _signerIndexes[signer] != 0;
    }

    /// @inheritdoc ISchnorrSetVerifier
    function getSigners() external view override returns (address[] memory) {
        LibSecp256k1.Point[] memory pubKeys = _getPubKeys();
        address[] memory signers = new address[](pubKeys.length-1);
        // 0 index is empty, we use 1-based indexing
        for (uint256 i = 0; i < signers.length; i++) {
            signers[i] = pubKeys[i+1].toAddress();
        }
        return signers;
    }

    /// @inheritdoc ISchnorrSetVerifier
    function getSignerIndex(address signer) external view override returns (uint256) {
        return _signerIndexes[signer];
    }

    /// @inheritdoc ISchnorrSetVerifier
    function getTotalSigners() external view override returns (uint256) { 
        return _getPubKeys().length - 1; // 0 index is empty
    }

    /// @inheritdoc ISchnorrSetVerifier
    function getSignerSetHash() external view override returns (bytes32) {
        return keccak256(SSTORE2.read(pointer));
    }

    function _getPubKeys() internal view returns (LibSecp256k1.Point[] memory) {
        return abi.decode(SSTORE2.read(pointer), (LibSecp256k1.Point[]));
    } 
}