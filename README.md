# Sunscreen SPF and Decryption Contracts

This repository contains contracts for interacting with Sunscreen's SPF (Secure Procesing Framework) and decryption service on EVM compatible chains. To include these contracts into your [`foundry`](https://getfoundry.sh/) project, use the following command to install the contracts as a dependency.

```bash
forge install sunscreen-tech/sunscreen-contracts
```

To enable simple importing in other contracts, update the `remappings.txt` file in your project to include the following.

```
@sunscreen/=lib/sunscreen-contracts/
```

You can then import the contracts in your Solidity files like so:

```solidity
import "@sunscreen/contracts/Spf.sol";
import "@sunscreen/contracts/TfheThresholdDecryption.sol";
```
