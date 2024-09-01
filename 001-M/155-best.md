Gentle Pink Kangaroo

High

# Incorrect Calculation of `pTokens` for Non-18 Decimal `rewardTokens`

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