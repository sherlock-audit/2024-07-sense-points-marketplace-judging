Nutty Candy Lemur

High

# Attacker will frontrun `PointTokenVault::claimPTokens()` and grief `Rumpel` wallet owners or users of the `PointTokenVault`

### Summary

`PointTokenVault::claimPTokens()` allows claiming `PTokens` from the merkle root on behalf of an `account` for better UX and gas sponsoring. It also lets users specify a `receiver` address to send the rewards to, if whitelisted in the `trustedClaimers()` mapping. 

The problem with this functionality is that it may lead to attackers doing unintended actions on behalf of the `account`, as the `account` may intend to send the `PTokens` to another `receiver`, but an attacker frontruns it and sends it to itself or vice-versa.

This would be relevant, for example, in case the ability to transfer `PTokens` was disabled in the `allowedCall` mapping in the `RumpelGuard`, which would mean claiming `PTokens` to the `Rumpel` wallet itself would not allow the `wallet` to sell the tokens or possibly even redeem via `redeemRewards()` if it was also not whitelisted.

### Root Cause

In `PointTokenVault:152`, it [allows](https://github.com/sherlock-audit/2024-07-sense-points-marketplace/blob/main/point-tokenization-vault/contracts/PointTokenVault.sol#L152) sending the tokens both to the `account` or a `trustedClaimers`, regardless of `msg.sender`, which means an attacker can frontrun the call and modify the `receiver` without reverting the transaction.

### Internal pre-conditions

None.

### External pre-conditions

None.

### Attack Path

1. Rumpel wallet calls `PointTokenVault::claimPTokens()` to claim to a certain receiver because `PToken::transfer()` is disabled or some other reason.
2. Attacker frontruns the transaction and claims to `account` instead.
3. The `PTokens` can not be transferred out of the `Rumpel` wallet unless for `PointTokenVault::redeemRewards()` if it is whitelisted.

### Impact

Stuck tokens.

### PoC

```solidity
function claimPTokens(Claim calldata _claim, address _account, address _receiver) public {
    ...
    if (_account != _receiver && !trustedClaimers[_account][_receiver]) {
        revert NotTrustedClaimer();
    }
    ...
}
```

### Mitigation

Usually when sponsoring transactions it's common to set a trusted `msg.sender` such that only this trusted user can pick the receiver of the `PTokens`.

The following is one example implementation preventing attackers from manipulating the receiver of the `PTokens`. The `trustedClaimers[_account][_receiver]` may be removed in case the `trustedCaller` can pick the correct `receiver`.

```solidity
function claimPTokens(Claim calldata _claim, address _account, address _receiver) public {
    ...
    if (_account != _receiver && (!trustedClaimers[_account][_receiver] || !trustedCaller[_account][msg.sender])) {
        revert NotTrustedClaimer();
    }
    ...
}
```