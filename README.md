# Issue M-1: Malicious user will use USDC permit functionality and sign message to steal reward tokens 

Source: https://github.com/sherlock-audit/2024-07-sense-points-marketplace-judging/issues/126 

## Found by 
0x73696d616f
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

# Issue M-2: Incorrect Calculation of `pTokens` for Non-18 Decimal `rewardTokens` 

Source: https://github.com/sherlock-audit/2024-07-sense-points-marketplace-judging/issues/155 

## Found by 
0xnbvc, Bbash, KupiaSec, Schereo, aman, phoenixv110
## Summary

The `convertRewardsToPTokens()` function assumes all `rewardTokens` have 18 decimals, which leads to incorrect minting of `pTokens` when dealing with tokens that have fewer decimals.

## Vulnerability Detail

[The sponsor confirmed](https://discord.com/channels/812037309376495636/1277643765133348956/1278664773449289823) that `rewardTokens` could be "any non-weird ERC20 token":

> Watson: Reward tokens can be pretty much any non-weird ERC20 token right?
> Sponsor: Yes

The function `convertRewardsToPTokens()` uses `FixedPointMathLib::divWadDown()` to calculate the number of `pTokens` to mint:

[PointTokenVault.sol#L244](https://github.com/sherlock-audit/2024-07-sense-points-marketplace/blob/076bf833f4dc1418e93c8172e4a4110344f1c812/point-tokenization-vault/contracts/PointTokenVault.sol#L244)
```solidity
uint256 pTokensToMint = FixedPointMathLib.divWadDown(_amountToConvert, rewardsPerPToken); // Round down for mint.
```

This calculation assumes both `_amountToConvert` and `rewardsPerPToken` are in 18 decimal precision. However, if the reward token has fewer decimals (e.g., 6 decimals like USDC), this calculation will result in an incorrect number of `pTokens` being minted.

## Impact

Users can mint significantly more `pTokens` than intended when converting reward tokens with fewer than 18 decimals. Incompatibility with non-18 decimals `rewardTokens`.

## Code Snippet

[PointTokenVault.sol#L244](https://github.com/sherlock-audit/2024-07-sense-points-marketplace/blob/076bf833f4dc1418e93c8172e4a4110344f1c812/point-tokenization-vault/contracts/PointTokenVault.sol#L244)

## Tool used

Manual Review

## Recommendation

Adjust the calculation to account for the actual decimals of the reward token:

```solidity
uint256 decimals = rewardToken.decimals();
uint256 scaleFactor = 10**(18 - decimals);
uint256 pTokensToMint = FixedPointMathLib.divWadDown(_amountToConvert * scaleFactor, rewardsPerPToken);
```

This scales up the `_amountToConvert` to 18 decimals before performing the division, ensuring correct calculation regardless of the reward token's decimals.

# Issue M-3: Malicious user will call `PointTokenVault::collectFees()` after a redemption was disabled to lose all `rewardTokenFeeAcc` 

Source: https://github.com/sherlock-audit/2024-07-sense-points-marketplace-judging/issues/185 

## Found by 
0x73696d616f
### Summary

The `solmate` `SafeTransferLib::safeTransfer()` does [not](https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol#L85) check if the token has code, which will not revert for an `address(0)` token. Thus, if redemptions are [disabled](https://github.com/sherlock-audit/2024-07-sense-points-marketplace/blob/main/point-tokenization-vault/contracts/PointTokenVault.sol#L312) (setting `redemptions[pointsId].rewardToken` is how redemptions are enabled), but there were fees in `rewardTokenFeeAcc[_pointsId]`, an attacker may call `PointTokenVault::collectFees()` to clear the fees mapping without transferring any tokens to the `feeCollector`.

### Root Cause

In [PointTokenVault:353](https://github.com/sherlock-audit/2024-07-sense-points-marketplace/blob/main/point-tokenization-vault/contracts/PointTokenVault.sol#L353), it does not check if the `rewardToken` is not null, allowing anyone to clear the mapping of the fees without the `feeCollector` ever receiving the tokens.

### Internal pre-conditions

1. Admins needs to disable redemptions (set `redemptions[pointsId].rewardToken` to `address(0)`) after fees have been accrued in `rewardTokenFeeAcc[_pointsId]`

### External pre-conditions

None.

### Attack Path

1. Users call `PointTokenVault::redeemRewards()` and add fees to `rewardTokenFeeAcc[pointsId]`.
2. Admin disables redemptions by setting `redemptions[pointsId].rewardToken` to `address(0)`, but there were fees in `rewardTokenFeeAcc[pointsId]` pending (could have been frontrun).
3. Attackers call `PointTokenVault::collectFees()` and clear the fees without sending tokens to the `feeCollector`.

### Impact

The protocol loses all fees.

### PoC

```solidity
function safeTransfer(address token, address to, uint256 amount) internal {
    /// @solidity memory-safe-assembly
    assembly {
        mstore(0x14, to) // Store the `to` argument.
        mstore(0x34, amount) // Store the `amount` argument.
        mstore(0x00, 0xa9059cbb000000000000000000000000) // `transfer(address,uint256)`.
        // Perform the transfer, reverting upon failure.
        if iszero(
            and( // The arguments of `and` are evaluated from right to left.
                or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20) //@audit returns 1 if token == address(0)
            )
        ) {
            mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
            revert(0x1c, 0x04)
        }
        mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten.
    }
}
```

### Mitigation

Explicitely check if the `rewardToken` is not null in `PointTokenVault::collectFees()` before claiming the fees.



## Discussion

**jparklev**

https://github.com/sense-finance/point-tokenization-vault/commit/d0933590c5de002a6025519e995dfd59a3648c7b

