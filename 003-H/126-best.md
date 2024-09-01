Nutty Candy Lemur

High

# Malicious user will use USDC permit functionality and sign message to steal reward tokens

### Summary

The `RumpelGuard` contains an `allowedCalls` mapping to whitelist target smart contracts and selector functions that each `Rumpel` wallet may call. This is intended to make sure `Rumpel` wallets do not claim rewards from external protocols for themselves and rely on the `PointTokenVault` instead. 

However, the `RumpelGuard` allows delegate calling to the `signMessageLib`, which allows setting a valid signature of the `Rumpel` wallet via `EIP1271`, which can be exploited by malicious users to use the USDC permit functionality and approve another address to steal the rewards from the wallet.

As usdc is in scope considering the fact that it is a non weird token in regards to the [scope](https://github.com/sherlock-audit/2024-07-sense-points-marketplace/tree/main?tab=readme-ov-file#q-if-you-are-integrating-tokens-are-you-allowing-only-whitelisted-tokens-to-work-with-the-codebase-or-any-complying-with-the-standard-are-they-assumed-to-have-certain-properties-eg-be-non-reentrant-are-there-any-types-of-weird-tokens-you-want-to-integrate) (it is non reentrant), the protocol gives explicit examples of whitelisted actions in the [readme](https://github.com/sherlock-audit/2024-07-sense-points-marketplace/blob/main/rumpel-wallet/README.md#rumpel-guard) (`USDC.transfer`) and it was confirmed by the sponsor that any non weird erc20 may be added as rewards, this attack allows users to steal reward tokens.

Additionally, the `Rumpel` wallet should be flexible in regards to claiming rewards for users, which means that claiming and sweeping rewards may not always be done [atomically](https://github.com/sherlock-audit/2024-07-sense-points-marketplace/blob/main/rumpel-wallet/README.md#rumpel-module), leaving a window of opportunity for malicious users to use the USDC permit functionality to steal rewards.
> It's expected that both of these actions will generally be done atomically, so that reward tokens don't sit in the user's wallet. However, we need to be flexible to different claiming mechanisms.

### Root Cause

In `RumpelGuard:57`, it does an early [return](https://github.com/sherlock-audit/2024-07-sense-points-marketplace/blob/main/rumpel-wallet/src/RumpelGuard.sol#L57) if `to == signMessageLib`, which means the wallet owners may use EIP1271 to validate any message.
In the USDC [code](https://etherscan.io/address/0x43506849d7c04f9138d1a2050bbf3a0c054402dd#code), `SignatureChecker.sol` checks EIP1271 signatures if the target is a smart contract, which the `Rumpel` wallet is.

### Internal pre-conditions

1. Admin needs to allow staking into an external protocol which sends usdc as rewards.

### External pre-conditions

1. None

### Attack Path

1. User stakes into the external protocol which gives usdc as rewards.
2. Admin allocates `ptokens` to this user.
3. User claims the rewards for itself via the USDC permit functionality by approving another address to transfer USDC out of the `Rumpel` wallet.

### Impact

The rewards from the external protocol are stolen which puts the protocol in risk of insolvency, not allowing users to redeem their ptokens for value.

### PoC

The `RumpelGuard` contains the mentioned early return in `checkTransaction()`, allowing any message to be signed via EIP1271.
```solidity
if (operation == Enum.Operation.DelegateCall) {
    if (to == signMessageLib) {
        return;
    }
    ...
}
```
USDC permit function fetches the EIP1271 signature if the target is a contract:
```solidity
function isValidSignatureNow(
    address signer,
    bytes32 digest,
    bytes memory signature
) external view returns (bool) {
    if (!isContract(signer)) {
        return ECRecover.recover(digest, signature) == signer;
    }
    return isValidERC1271SignatureNow(signer, digest, signature);
}

function isValidERC1271SignatureNow(
    address signer,
    bytes32 digest,
    bytes memory signature
) internal view returns (bool) {
    (bool success, bytes memory result) = signer.staticcall(
        abi.encodeWithSelector(
            IERC1271.isValidSignature.selector,
            digest,
            signature
        )
    );
    return (success &&
        result.length >= 32 &&
        abi.decode(result, (bytes32)) ==
        bytes32(IERC1271.isValidSignature.selector));
}
```

### Mitigation

The messages that can be signed must be whitelisted by the protocol, otherwise `Rumpel` wallet owners will leverage `EIP1271` signatures to steal funds from the protocol.