Nutty Candy Lemur

Medium

# Malicious user will call `PointTokenVault::collectFees()` after a redemption was disabled to lose all `rewardTokenFeeAcc`

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