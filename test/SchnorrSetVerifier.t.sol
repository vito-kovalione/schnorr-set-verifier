// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {SchnorrSetVerifier} from "../src/SchnorrSetVerifier.sol";
import {LibSecp256k1} from "../src/libs/LibSecp256k1.sol";
import {LibSchnorr} from "../src/libs/LibSchnorr.sol";
import {LibSchnorrExtended} from "./libs/LibSchnorrExtended.sol";
import {LibSecp256k1Extended} from "./libs/LibSecp256k1Extended.sol";
import {ISchnorrSetVerifierErrors} from "../src/interfaces/ISchnorrSetVerifierErrors.sol";
import {ISchnorrSetVerifierStructs} from "../src/interfaces/ISchnorrSetVerifierStructs.sol";

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
        verifier = new SchnorrSetVerifier();
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
        vm.expectRevert(ISchnorrSetVerifierErrors.NotOwner.selector);
        verifier.setMinSignaturesThreshold(3);
        vm.stopPrank();
    }

    function test_setMinSignaturesThreshold_RevertIfZero() public {
        vm.startPrank(owner);
        vm.expectRevert(ISchnorrSetVerifierErrors.ZeroValue.selector);
        verifier.setMinSignaturesThreshold(0);
        vm.stopPrank();
    }

    function test_AddSigner() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({
            x: 1,
            y: 2
        });
        address signer = pubKey.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey);
        vm.stopPrank();

        assertTrue(verifier.isSigner(signer));
        assertEq(verifier.getSignerIndex(signer), 1);
        assertEq(verifier.getTotalSigners(), 1);
    }

    function test_AddSigner_RevertIfNotOwner() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({
            x: 1,
            y: 2
        });

        vm.startPrank(nonOwner);
        vm.expectRevert(ISchnorrSetVerifierErrors.NotOwner.selector);
        verifier.addSigner(pubKey);
        vm.stopPrank();
    }

    function test_AddSigner_RevertIfAlreadyAdded() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({
            x: 1,
            y: 2
        });
        address signer = pubKey.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey);
        vm.expectRevert(abi.encodeWithSelector(ISchnorrSetVerifierErrors.SignerAlreadyAdded.selector, signer));
        verifier.addSigner(pubKey);
        vm.stopPrank();
    }

    function test_RemoveSigner() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({
            x: 1,
            y: 2
        });
        address signer = pubKey.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey);
        verifier.removeSigner(signer);
        vm.stopPrank();

        assertFalse(verifier.isSigner(signer));
        assertEq(verifier.getTotalSigners(), 0);
    }

    function test_RemoveSigner_RevertIfNotOwner() public {
        LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({
            x: 1,
            y: 2
        });
        address signer = pubKey.toAddress();

        vm.startPrank(owner);
        verifier.addSigner(pubKey);
        vm.stopPrank();

        vm.startPrank(nonOwner);
        vm.expectRevert(ISchnorrSetVerifierErrors.NotOwner.selector);
        verifier.removeSigner(signer);
        vm.stopPrank();
    }

    function test_RemoveSigner_RevertIfNotSigner() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(ISchnorrSetVerifierErrors.NotSigner.selector, address(1)));
        verifier.removeSigner(address(1));
        vm.stopPrank();
    }

    function test_GetSigners() public {
        LibSecp256k1.Point memory pubKey1 = LibSecp256k1.Point({
            x: 1,
            y: 2
        });
        LibSecp256k1.Point memory pubKey2 = LibSecp256k1.Point({
            x: 3,
            y: 4
        });
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

        SchnorrSetVerifier.SchnorrSignature memory schnorrData = ISchnorrSetVerifierStructs.SchnorrSignature({
            signature: bytes32(signature),
            commitment: commitment,
            signers: signerIndices
        });

        // Verify signature
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

        // Create invalid signature data
        uint256[] memory signerIndices = new uint256[](3);
        signerIndices[0] = 1;
        signerIndices[1] = 2;
        signerIndices[2] = 3;

        SchnorrSetVerifier.SchnorrSignature memory schnorrData = ISchnorrSetVerifierStructs.SchnorrSignature({
            signature: bytes32(0), // Invalid signature
            commitment: address(1), // Invalid commitment
            signers: signerIndices
        });

        // Verify signature should revert
        vm.expectRevert(ISchnorrSetVerifierErrors.InvalidSignature.selector);
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

        SchnorrSetVerifier.SchnorrSignature memory schnorrData = ISchnorrSetVerifierStructs.SchnorrSignature({
            signature: bytes32(signature),
            commitment: commitment,
            signers: signerIndices
        });

        // Verify signature should revert
        vm.expectRevert(abi.encodeWithSelector(ISchnorrSetVerifierErrors.NotEnoughSignatures.selector, 2, 3));
        verifier.verifySignature(message, schnorrData);
    }

    function test_RemoveSigner_FromMiddle() public {
        // Add three signers
        LibSecp256k1.Point memory pubKey1 = LibSecp256k1.Point({
            x: 1,
            y: 2
        });
        LibSecp256k1.Point memory pubKey2 = LibSecp256k1.Point({
            x: 3,
            y: 4
        });
        LibSecp256k1.Point memory pubKey3 = LibSecp256k1.Point({
            x: 5,
            y: 6
        });
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
        LibSecp256k1.Point memory pubKey1 = LibSecp256k1.Point({
            x: 1,
            y: 2
        });
        LibSecp256k1.Point memory pubKey2 = LibSecp256k1.Point({
            x: 3,
            y: 4
        });
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
        LibSecp256k1.Point memory pubKey1 = LibSecp256k1.Point({
            x: 1,
            y: 2
        });
        LibSecp256k1.Point memory pubKey2 = LibSecp256k1.Point({
            x: 3,
            y: 4
        });
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
        LibSecp256k1.Point memory pubKey1 = LibSecp256k1.Point({
            x: 1,
            y: 2
        });
        LibSecp256k1.Point memory pubKey2 = LibSecp256k1.Point({
            x: 3,
            y: 4
        });
        LibSecp256k1.Point memory pubKey3 = LibSecp256k1.Point({
            x: 5,
            y: 6
        });
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

    function _addSigners(uint256 count) internal returns (uint256[] memory privateKeys) {
        privateKeys = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 privateKey = uint256(keccak256(abi.encodePacked(i)));
            Vm.Wallet memory wallet = vm.createWallet(privateKey);
            LibSecp256k1.Point memory pubKey = LibSecp256k1.Point({x: wallet.publicKeyX, y: wallet.publicKeyY});
            verifier.addSigner(pubKey);
            privateKeys[i] = privateKey;
        }
    }
} 