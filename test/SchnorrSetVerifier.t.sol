// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";

import {LibSchnorrExtended} from "./libs/LibSchnorrExtended.sol";
import {LibSecp256k1Extended} from "./libs/LibSecp256k1Extended.sol";
import {LibSecp256k1} from "scribe/src/libs/LibSecp256k1.sol";
import {LibSchnorr} from "scribe/src/libs/LibSchnorr.sol";
import {Ownable2Step} from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";

import {ISchnorrSetVerifier} from "../src/interfaces/ISchnorrSetVerifier.sol";
import {SchnorrSetVerifier} from "../src/SchnorrSetVerifier.sol";

contract SchnorrSetVerifierTest is Test {
    using LibSchnorr for LibSecp256k1.Point;
    using LibSecp256k1 for LibSecp256k1.Point;
    using LibSecp256k1 for LibSecp256k1.JacobianPoint;
    using LibSecp256k1Extended for uint;
    using LibSchnorrExtended for uint256[];

    SchnorrSetVerifier public verifier;
    address public owner;
    address public nonOwner;

    function setUp() public {
        owner = makeAddr("owner");
        nonOwner = makeAddr("nonOwner");
        vm.startPrank(owner);
        verifier = new SchnorrSetVerifier(owner);
        Ownable2Step(address(verifier)).transferOwnership(owner);
        Ownable2Step(address(verifier)).acceptOwnership();
        vm.stopPrank();
    }

    function test_Constructor() public view {
        assertEq(verifier.getTotalSigners(), 0);
        assertEq(verifier.minSignaturesThreshold(), 0);
    }

    function test_setMinSignaturesThreshold() public {
        vm.startPrank(owner);
        verifier.setMinSignaturesThreshold(3);
        assertEq(verifier.minSignaturesThreshold(), 3);
        vm.stopPrank();
    }

    function test_setMinSignaturesThreshold_RevertIfNotOwner() public {
        vm.startPrank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                nonOwner
            )
        );
        verifier.setMinSignaturesThreshold(3);
        vm.stopPrank();
    }

    function test_setMinSignaturesThreshold_RevertIfZero() public {
        vm.startPrank(owner);
        vm.expectRevert(ISchnorrSetVerifier.ZeroValue.selector);
        verifier.setMinSignaturesThreshold(0);
        vm.stopPrank();
    }

    function test_AddSigner() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({x: 1, y: 2});
        address signer = pubKey.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey);
        vm.stopPrank();

        assertTrue(verifier.isSigner(signer));
        assertEq(verifier.getSignerIndex(signer), 1);
        assertEq(verifier.getTotalSigners(), 1);
    }

    function test_AddSigner_MaxSigners() public {
        vm.startPrank(owner);
        for (uint256 i = 1; i < 382; i++) {
            verifier.addSigner(i.derivePublicKey());
        }
        vm.stopPrank();

        address pointer = SchnorrSetVerifier(address(verifier)).pointer();
        console.log(pointer.code.length);

        assertEq(verifier.getTotalSigners(), 381);
        address[] memory signers = verifier.getSigners();
        assertEq(signers.length, 381);
        assertEq(signers[0], uint256(1).derivePublicKey().toAddress());
        assertEq(signers[380], uint256(381).derivePublicKey().toAddress());
    }

    function test_AddSigner_RevertIfMaxSignersReached() public {
        vm.startPrank(owner);
        for (uint256 i = 1; i < 382; i++) {
            verifier.addSigner(i.derivePublicKey());
        }
        vm.expectRevert(ISchnorrSetVerifier.MaxSignersReached.selector);
        verifier.addSigner(uint256(382).derivePublicKey());
        vm.stopPrank();
    }

    function test_AddSigner_RevertIfNotOwner() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({x: 1, y: 2});

        vm.startPrank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                nonOwner
            )
        );
        verifier.addSigner(pubKey);
        vm.stopPrank();
    }

    function test_AddSigner_RevertIfAlreadyAdded() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({x: 1, y: 2});
        address signer = pubKey.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISchnorrSetVerifier.SignerAlreadyAdded.selector,
                signer
            )
        );
        verifier.addSigner(pubKey);
        vm.stopPrank();
    }

    function test_AddSigner_RevertIfZeroPoint() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({x: 0, y: 0});
        vm.startPrank(owner);
        vm.expectRevert(ISchnorrSetVerifier.InvalidPublicKey.selector);
        verifier.addSigner(pubKey);
        vm.stopPrank();
    }

    // function test_AddSigner_RevertIfZeroAddress() public {
    //     // Create a point that is not a zero point but whose toAddress() returns zero
    //     // This is extremely unlikely to happen in practice, but we can force it for testing
    //     LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({
    //         x: 0x1234567890123456789012345678901234567890123456789012345678901234,
    //         y: 0x1234567890123456789012345678901234567890123456789012345678901234
    //     });
        
    //     // Mock the toAddress function to return zero address
    //     vm.mockCall(
    //         address(0), // any address will do since we're mocking a library function
    //         abi.encodeWithSelector(LibSecp256k1.Point.toAddress.selector, pubKey),
    //         abi.encode(address(0))
    //     );

    //     vm.startPrank(owner);
    //     vm.expectRevert(ISchnorrSetVerifier.ZeroAddress.selector);
    //     verifier.addSigner(pubKey);
    //     vm.stopPrank();
    // }

    function test_RemoveSigner() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({x: 1, y: 2});
        address signer = pubKey.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey);
        verifier.removeSigner(signer);
        vm.stopPrank();

        assertFalse(verifier.isSigner(signer));
        assertEq(verifier.getTotalSigners(), 0);
    }

    function test_RemoveSigner_RevertIfNotOwner() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({x: 1, y: 2});
        address signer = pubKey.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey);
        vm.stopPrank();

        vm.startPrank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                nonOwner
            )
        );
        verifier.removeSigner(signer);
        vm.stopPrank();
    }

    function test_RemoveSigner_RevertIfNotSigner() public {
        vm.startPrank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISchnorrSetVerifier.NotSigner.selector,
                address(1)
            )
        );
        verifier.removeSigner(address(1));
        vm.stopPrank();
    }

    function test_GetSigners() public {
        LibSecp256k1.Point memory pubKey1 = LibSecp256k1.Point({x: 1, y: 2});
        LibSecp256k1.Point memory pubKey2 = LibSecp256k1.Point({x: 3, y: 4});
        address signer1 = pubKey1.toAddress();
        address signer2 = pubKey2.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey1);
        verifier.addSigner(pubKey2);
        vm.stopPrank();

        address[] memory signers = verifier.getSigners();
        assertEq(signers.length, 2);
        assertEq(signers[0], signer1);
        assertEq(signers[1], signer2);
    }

    function test_VerifySignature() public {
        // Add signers to the contract
        vm.startPrank(owner);
        uint256[] memory privKeys = _addSigners(3);
        verifier.setMinSignaturesThreshold(3);
        vm.stopPrank();

        // Generate message
        bytes32 message = keccak256("test message");

        // Generate multi-signature using LibSchnorrExtended
        (uint256 signature, address commitment) = privKeys.signMessage(message);

        // Create signature data for verification
        uint256[] memory signerIndices = new uint256[](3);
        signerIndices[0] = 1;
        signerIndices[1] = 2;
        signerIndices[2] = 3;

        SchnorrSetVerifier.SchnorrSignature
            memory schnorrData = ISchnorrSetVerifier.SchnorrSignature({
                signature: bytes32(signature),
                commitment: commitment,
                signers: signerIndices
            });

        // Verify signature
        verifier.verifySignature(message, schnorrData);
    }

    function test_VerifySignature_RevertIfEmptySignature() public {
        // Generate private keys for signers
        uint256[] memory privKeys = new uint256[](3);
        privKeys[0] = 1;
        privKeys[1] = 2;
        privKeys[2] = 3;

        // Add signers to the contract
        vm.startPrank(owner);
        for (uint i = 0; i < privKeys.length; i++) {
            LibSecp256k1.Point memory pubKey = privKeys[i].derivePublicKey();
            verifier.addSigner(pubKey);
        }
        verifier.setMinSignaturesThreshold(3);
        vm.stopPrank();

        // Generate message
        bytes32 message = keccak256("test message");

        // Create invalid signature data
        uint256[] memory signerIndices = new uint256[](3);
        signerIndices[0] = 1;
        signerIndices[1] = 2;
        signerIndices[2] = 3;

        SchnorrSetVerifier.SchnorrSignature
            memory schnorrData = ISchnorrSetVerifier.SchnorrSignature({
                signature: bytes32(0), // Invalid signature
                commitment: address(1), // Invalid commitment
                signers: signerIndices
            });

        // Verify signature should revert
        vm.expectRevert(ISchnorrSetVerifier.InvalidSignature.selector);
        verifier.verifySignature(message, schnorrData);
    }

    function test_VerifySignature_RevertIfEmptyCommitment() public {
        // Generate private keys for signers
        uint256[] memory privKeys = new uint256[](3);
        privKeys[0] = 1;
        privKeys[1] = 2;
        privKeys[2] = 3;

        // Add signers to the contract
        vm.startPrank(owner);
        for (uint i = 0; i < privKeys.length; i++) {
            LibSecp256k1.Point memory pubKey = privKeys[i].derivePublicKey();
            verifier.addSigner(pubKey);
        }
        verifier.setMinSignaturesThreshold(3);
        vm.stopPrank();

        // Generate message
        bytes32 message = keccak256("test message");

        // Generate multi-signature using LibSchnorrExtended
        (uint256 signature, address commitment) = privKeys.signMessage(message);

        // Create invalid signature data
        uint256[] memory signerIndices = new uint256[](3);
        signerIndices[0] = 1;
        signerIndices[1] = 2;
        signerIndices[2] = 3;

        SchnorrSetVerifier.SchnorrSignature
            memory schnorrData = ISchnorrSetVerifier.SchnorrSignature({
                signature: bytes32(signature),
                commitment: address(0), // Invalid commitment
                signers: signerIndices
            });

        // Verify signature should revert
        vm.expectRevert(ISchnorrSetVerifier.InvalidCommitment.selector);
        verifier.verifySignature(message, schnorrData);
    }

    function test_VerifySignature_RevertIfInvalidSignature() public {
        // Generate private keys for signers
        uint256[] memory privKeys = new uint256[](3);
        privKeys[0] = 1;
        privKeys[1] = 2;
        privKeys[2] = 3;

        // Add signers to the contract
        vm.startPrank(owner);
        for (uint i = 0; i < privKeys.length; i++) {
            LibSecp256k1.Point memory pubKey = privKeys[i].derivePublicKey();
            verifier.addSigner(pubKey);
        }
        verifier.setMinSignaturesThreshold(3);
        vm.stopPrank();

        // Generate message
        bytes32 message = keccak256("test message");

        // Generate multi-signature using LibSchnorrExtended
        (uint256 signature, address commitment) = privKeys.signMessage(message);

        // Create signature data with invalid signature
        uint256[] memory signerIndices = new uint256[](3);
        signerIndices[0] = 1;
        signerIndices[1] = 2;
        signerIndices[2] = 3;

        SchnorrSetVerifier.SchnorrSignature
            memory schnorrData = ISchnorrSetVerifier.SchnorrSignature({
                signature: bytes32(signature + 1),
                commitment: commitment,
                signers: signerIndices
            });

        // Verify signature should revert
        vm.expectRevert(ISchnorrSetVerifier.InvalidSignature.selector);
        verifier.verifySignature(message, schnorrData);
    }

    function test_VerifySignature_RevertIfEmptySigners() public {
        // Generate private keys for signers
        uint256[] memory privKeys = new uint256[](3);
        privKeys[0] = 1;
        privKeys[1] = 2;
        privKeys[2] = 3;

        // Add signers to the contract
        vm.startPrank(owner);
        for (uint i = 0; i < privKeys.length; i++) {
            LibSecp256k1.Point memory pubKey = privKeys[i].derivePublicKey();
            verifier.addSigner(pubKey);
        }
        verifier.setMinSignaturesThreshold(3);
        vm.stopPrank();

        // Generate message
        bytes32 message = keccak256("test message");

        // Generate multi-signature using LibSchnorrExtended
        (uint256 signature, address commitment) = privKeys.signMessage(message);

        // Create signature data with invalid signers order
        uint256[] memory signerIndices = new uint256[](0);

        SchnorrSetVerifier.SchnorrSignature
            memory schnorrData = ISchnorrSetVerifier.SchnorrSignature({
                signature: bytes32(signature),
                commitment: commitment,
                signers: signerIndices
            });

        // Verify signature should revert
        vm.expectRevert(ISchnorrSetVerifier.InvalidSignersOrder.selector);
        verifier.verifySignature(message, schnorrData);
    }

    function test_VerifySignature_RevertIfInvalidSignersOrder() public {
        // Generate private keys for signers
        uint256[] memory privKeys = new uint256[](3);
        privKeys[0] = 1;
        privKeys[1] = 2;
        privKeys[2] = 3;

        // Add signers to the contract
        vm.startPrank(owner);
        for (uint i = 0; i < privKeys.length; i++) {
            LibSecp256k1.Point memory pubKey = privKeys[i].derivePublicKey();
            verifier.addSigner(pubKey);
        }
        verifier.setMinSignaturesThreshold(3);
        vm.stopPrank();

        // Generate message
        bytes32 message = keccak256("test message");

         // Generate multi-signature using LibSchnorrExtended
        (uint256 signature, address commitment) = privKeys.signMessage(message);

        // Create signature data with invalid signers order
        uint256[] memory signerIndices = new uint256[](3);
        signerIndices[0] = 2;
        signerIndices[1] = 1;
        signerIndices[2] = 3;

        SchnorrSetVerifier.SchnorrSignature
            memory schnorrData = ISchnorrSetVerifier.SchnorrSignature({
                signature: bytes32(signature),
                commitment: commitment,
                signers: signerIndices
            });

        // Verify signature should revert
        vm.expectRevert(ISchnorrSetVerifier.InvalidSignersOrder.selector);
        verifier.verifySignature(message, schnorrData);
    }

    function test_VerifySignature_RevertIfNotEnoughSignatures() public {
        // Generate private keys for signers
        uint256[] memory privKeys = new uint256[](3);
        privKeys[0] = 1;
        privKeys[1] = 2;
        privKeys[2] = 3;

        // Add signers to the contract
        vm.startPrank(owner);
        for (uint i = 0; i < privKeys.length; i++) {
            LibSecp256k1.Point memory pubKey = privKeys[i].derivePublicKey();
            verifier.addSigner(pubKey);
        }
        verifier.setMinSignaturesThreshold(3);
        vm.stopPrank();

        // Generate message
        bytes32 message = keccak256("test message");

        // Generate multi-signature using LibSchnorrExtended
        (uint256 signature, address commitment) = privKeys.signMessage(message);

        // Create signature data with only 2 signers
        uint256[] memory signerIndices = new uint256[](2);
        signerIndices[0] = 1;
        signerIndices[1] = 2;

        SchnorrSetVerifier.SchnorrSignature
            memory schnorrData = ISchnorrSetVerifier.SchnorrSignature({
                signature: bytes32(signature),
                commitment: commitment,
                signers: signerIndices
            });

        // Verify signature should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ISchnorrSetVerifier.NotEnoughSignatures.selector,
                2,
                3
            )
        );
        verifier.verifySignature(message, schnorrData);
    }

    function test_VerifySignature_RevertIfInvalidIndex() public {
        // Generate private keys for signers
        uint256[] memory privKeys = new uint256[](3);
        privKeys[0] = 1;
        privKeys[1] = 2;
        privKeys[2] = 3;

        // Add signers to the contract
        vm.startPrank(owner);
        for (uint i = 0; i < privKeys.length; i++) {
            LibSecp256k1.Point memory pubKey = privKeys[i].derivePublicKey();
            verifier.addSigner(pubKey);
        }
        verifier.setMinSignaturesThreshold(3);
        vm.stopPrank();

        // Generate message
        bytes32 message = keccak256("test message");

        // Generate multi-signature using LibSchnorrExtended
        (uint256 signature, address commitment) = privKeys.signMessage(message);

        // Create signature data with only 2 signers
        uint256[] memory signerIndices = new uint256[](3);
        signerIndices[0] = 1;
        signerIndices[1] = 2;
        signerIndices[2] = 10;

        SchnorrSetVerifier.SchnorrSignature
            memory schnorrData = ISchnorrSetVerifier.SchnorrSignature({
                signature: bytes32(signature),
                commitment: commitment,
                signers: signerIndices
            });

        // Verify signature should revert
         vm.expectRevert(
            abi.encodeWithSelector(
                ISchnorrSetVerifier.InvalidIndex.selector,
                10
            )
        );
        verifier.verifySignature(message, schnorrData);
    }

    function test_RemoveSigner_FromMiddle() public {
        // Add three signers
        LibSecp256k1.Point memory pubKey1 = LibSecp256k1.Point({x: 1, y: 2});
        LibSecp256k1.Point memory pubKey2 = LibSecp256k1.Point({x: 3, y: 4});
        LibSecp256k1.Point memory pubKey3 = LibSecp256k1.Point({x: 5, y: 6});
        address signer1 = pubKey1.toAddress();
        address signer2 = pubKey2.toAddress();
        address signer3 = pubKey3.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey1);
        verifier.addSigner(pubKey2);
        verifier.addSigner(pubKey3);

        // Remove middle signer
        verifier.removeSigner(signer2);
        vm.stopPrank();

        // Verify state after removal
        assertFalse(verifier.isSigner(signer2));
        assertTrue(verifier.isSigner(signer1));
        assertTrue(verifier.isSigner(signer3));
        assertEq(verifier.getTotalSigners(), 2);

        // Verify signers array order
        address[] memory signers = verifier.getSigners();
        assertEq(signers.length, 2);
        assertEq(signers[0], signer1);
        assertEq(signers[1], signer3);
    }

    function test_RemoveSigner_LastSigner() public {
        // Add two signers
        LibSecp256k1.Point memory pubKey1 = LibSecp256k1.Point({x: 1, y: 2});
        LibSecp256k1.Point memory pubKey2 = LibSecp256k1.Point({x: 3, y: 4});
        address signer1 = pubKey1.toAddress();
        address signer2 = pubKey2.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey1);
        verifier.addSigner(pubKey2);

        // Remove last signer
        verifier.removeSigner(signer2);
        vm.stopPrank();

        // Verify state after removal
        assertFalse(verifier.isSigner(signer2));
        assertTrue(verifier.isSigner(signer1));
        assertEq(verifier.getTotalSigners(), 1);

        // Verify signers array
        address[] memory signers = verifier.getSigners();
        assertEq(signers.length, 1);
        assertEq(signers[0], signer1);
    }

    function test_RemoveSigner_FirstSigner() public {
        // Add two signers
        LibSecp256k1.Point memory pubKey1 = LibSecp256k1.Point({x: 1, y: 2});
        LibSecp256k1.Point memory pubKey2 = LibSecp256k1.Point({x: 3, y: 4});
        address signer1 = pubKey1.toAddress();
        address signer2 = pubKey2.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey1);
        verifier.addSigner(pubKey2);

        // Remove first signer
        verifier.removeSigner(signer1);
        vm.stopPrank();

        // Verify state after removal
        assertFalse(verifier.isSigner(signer1));
        assertTrue(verifier.isSigner(signer2));
        assertEq(verifier.getTotalSigners(), 1);

        // Verify signers array
        address[] memory signers = verifier.getSigners();
        assertEq(signers.length, 1);
        assertEq(signers[0], signer2);
    }

    function test_RemoveSigner_VerifyIndexes() public {
        // Add three signers
        LibSecp256k1.Point memory pubKey1 = LibSecp256k1.Point({x: 1, y: 2});
        LibSecp256k1.Point memory pubKey2 = LibSecp256k1.Point({x: 3, y: 4});
        LibSecp256k1.Point memory pubKey3 = LibSecp256k1.Point({x: 5, y: 6});
        address signer1 = pubKey1.toAddress();
        address signer2 = pubKey2.toAddress();
        address signer3 = pubKey3.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey1);
        verifier.addSigner(pubKey2);
        verifier.addSigner(pubKey3);

        // Remove middle signer
        verifier.removeSigner(signer2);

        // Verify indexes are updated correctly
        assertEq(verifier.getSignerIndex(signer1), 1);
        assertEq(verifier.getSignerIndex(signer3), 2);
        assertEq(verifier.getSignerIndex(signer2), 0); // removed signer should have index 0

        // Remove first signer
        verifier.removeSigner(signer1);

        // Verify indexes are updated correctly
        assertEq(verifier.getSignerIndex(signer3), 1);
        assertEq(verifier.getSignerIndex(signer1), 0); // removed signer should have index 0
        vm.stopPrank();
    }

    function _addSigners(
        uint256 count
    ) internal returns (uint256[] memory privateKeys) {
        privateKeys = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 privateKey = uint256(keccak256(abi.encodePacked(i)));
            Vm.Wallet memory wallet = vm.createWallet(privateKey);
            LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({
                x: wallet.publicKeyX,
                y: wallet.publicKeyY
            });
            verifier.addSigner(pubKey);
            privateKeys[i] = privateKey;
        }
    }

    // --- Additional tests for 100% coverage ---
    function test_GetSignerSetHash_EmptyAndAfterAddRemove() public {
        // Hash with no signers
        bytes32 emptyHash = verifier.getSignerSetHash();

        // Add a signer
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({x: 1, y: 2});
        vm.startPrank(owner);
        verifier.addSigner(pubKey);
        vm.stopPrank();
        bytes32 hashAfterAdd = verifier.getSignerSetHash();
        assertTrue(hashAfterAdd != emptyHash);

        // Remove the signer
        address signer = pubKey.toAddress();
        vm.startPrank(owner);
        verifier.removeSigner(signer);
        vm.stopPrank();
        bytes32 hashAfterRemove = verifier.getSignerSetHash();
        assertEq(hashAfterRemove, emptyHash);
    }

    function test_Pointer_ChangesOnAddRemove() public {
        address pointerBefore = verifier.pointer();
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({x: 1, y: 2});
        vm.startPrank(owner);
        verifier.addSigner(pubKey);
        address pointerAfterAdd = verifier.pointer();
        assertTrue(pointerAfterAdd != pointerBefore);
        verifier.removeSigner(pubKey.toAddress());
        address pointerAfterRemove = verifier.pointer();
        assertTrue(pointerAfterRemove != pointerAfterAdd);
        vm.stopPrank();
    }

    function test_GetSignerIndex_NeverAddedAddress() public view {
        address neverAdded = address(0x1234);
        assertEq(verifier.getSignerIndex(neverAdded), 0);
    }

    function test_GetSigners_Empty() public view {
        address[] memory signers = verifier.getSigners();
        assertEq(signers.length, 0);
    }

    function test_GetTotalSigners_Empty() public view {
        assertEq(verifier.getTotalSigners(), 0);
    }

    function test_IsSigner_NeverAddedAddress() public view {
        address neverAdded = address(0x5678);
        assertFalse(verifier.isSigner(neverAdded));
    }
}
