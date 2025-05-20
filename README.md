# Schnorr Set Verifier

A Solidity smart contract implementation for verifying Schnorr signatures from a set of authorized signers. This contract allows for efficient management and verification of Schnorr signatures from a predefined set of public keys.

## Overview

The Schnorr Set Verifier is designed to:
- Manage a set of authorized signers with their public keys
- Verify Schnorr signatures against a threshold of required signers
- Efficiently store and retrieve signer public keys using SSTORE2
- Support up to 379 signers in the set

## Features

- **Schnorr Signature Verification**: Verify signatures using the Schnorr signature scheme
- **Threshold-based Verification**: Require a minimum number of signatures for verification
- **Efficient Storage**: Uses SSTORE2 for gas-efficient storage of public keys
- **Signer Management**: Add and remove signers with proper access control
- **Gas Optimization**: Optimized assembly code for efficient storage operations

## Technical Details

### Schnorr Signature Scheme
The contract implements the Schnorr signature scheme for the secp256k1 curve, which provides:
- Efficient signature aggregation
- Compact signature representation
- Strong security guarantees

### Storage Optimization
- Uses SSTORE2 for efficient storage of public keys
- Implements 1-based indexing for signer management
- Optimized assembly code for storage operations
- Maximum of 379 signers to prevent storage issues and maintain gas efficiency

### Dependencies
- **LibSecp256k1**: Elliptic curve operations for secp256k1
- **LibSchnorr**: Schnorr signature scheme implementation
- **SSTORE2**: Gas-efficient storage solution for contract data

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Solidity ^0.8.0

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/schnorr-set-verifier.git
cd schnorr-set-verifier
```

2. Install dependencies:
```bash
forge install
```

## Usage

### Building

```bash
forge build
```

### Testing

Run all tests:
```bash
forge test
```

Run specific test file:
```bash
forge test --match-path test/SchnorrSetVerifier.t.sol
```

Generate coverage report:
```bash
forge coverage
```

Generate gas report:
```bash
forge snapshot
```

## Contract Interface

### Key Functions

- `addSigner(LibSecp256k1.Point memory signerPubKey)`: Add a new signer to the set
- `removeSigner(address signer)`: Remove a signer from the set
- `verifySignature(bytes32 message, SchnorrSignature calldata schnorrData)`: Verify a Schnorr signature
- `setMinSignaturesThreshold(uint256 newThreshold)`: Set the minimum number of required signatures
- `isSigner(address signer)`: Check if an address is an authorized signer
- `getSigners()`: Get all authorized signers
- `getTotalSigners()`: Get the total number of signers
- `getSignerSetHash()`: Get the hash of the current signer set

### Events

- `LogSignerAdded(address indexed signer, uint256 index, address pointer)`
- `LogSignerRemoved(address indexed signer, uint256 index, address pointer)`
- `LogThresholdUpdated(uint256 newThreshold)`

## Security

- Only the contract owner can add/remove signers
- Signatures are verified using the Schnorr signature scheme
- Public keys are validated before being added
- Maximum signer limit of 379 to prevent storage issues
- All public keys are validated to ensure they are valid points on the secp256k1 curve
- Signer indices are validated to prevent out-of-bounds access
- Signer order is enforced to prevent signature replay attacks

## Gas Optimization

- Uses SSTORE2 for efficient storage of public keys
- Implements assembly code for optimized storage operations
- Minimizes storage reads/writes during signature verification
- Efficient public key aggregation using Jacobian coordinates

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.
