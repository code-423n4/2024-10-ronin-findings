| Number | Title |
|-------|-------|
| L1    | noDelegateCall modifier missing |
| L2    | Silent underflow in amount0 - burnedLiquidityOwed.token0 |
| L3    | Unexpected token burn when collecting fees |

# L1 - noDelegateCall modifier is missing

This post explains why the no delegate call is needed.

https://www.rareskills.io/post/nodelegatecall

> Uniswap V2 is the most forked DeFi protocol in history. The Uniswap V2 protocol faced competition from projects copying the source code line-by-line and marketing the new product as an alternative to Uniswap V2 and sometimes incentivizing users by providing airdrops.

> To prevent this from happening, the Uniswap team licensed Uniswap V3 under the Business Source License — anyone can copy the code but it cannot be used for commercial purposes until the license expired in April 2023.

> However, if someone wanted to make a “copy” of Uniswap V3 they could simply create a clone proxy and point it to an instance of Uniswap V3 — then market that smart contract as an alternative to Uniswap V3. The nodelegatecall modifier prevents this from happening.

the old code has the [noDelegateCall modifier](https://github.com/Uniswap/v3-core/blob/d8b1c635c275d2a9450bd6a78f3fa2484fef73eb/contracts/UniswapV3Pool.sol#L308)

However, this modifier are removed in the katana pool contract.

then if someone wanted to make a “copy” of Uniswap V3 they could simply create a clone proxy and point it to an instance of Katana V3 — then market that smart contract as an alternative to Katana v3.

# L2 - amount0 - burnedLiquidityOwed.token0 sliently underflow in NonfungiblePositionManager.sol

In NonfungiblePositionManager.sol, the new code below can [sliently underflow](https://github.com/ronin-chain/katana-v3-contracts/blob/03c80179e04f40d96f06c451ea494bb18f2a58fc/src/periphery/NonfungiblePositionManager.sol#L401) because the solidity compiler version is below 0.8.0

```solidity
    // the actual amounts collected are returned
    (amount0, amount1) = pool.collect(recipient, position.tickLower, position.tickUpper, amount0Collect, amount1Collect);

    CollectedFees storage fees = _collectedFees[params.tokenId];
    BurnedLiquidityOwed storage burnedLiquidityOwed = _burnedLiquidityOwed[params.tokenId];
    // we record only the fees collected, not wholly the tokens owed
    fees.token0 += amount0 - burnedLiquidityOwed.token0; // @audit underflow
    fees.token1 += amount1 - burnedLiquidityOwed.token1; // @audit underflow
    (burnedLiquidityOwed.token0, burnedLiquidityOwed.token1) = (0, 0);
```

This underflow only impact the veiw function 

```solidity
  /// @inheritdoc INonfungiblePositionManager
  function collectedFees(uint256 tokenId) external view override returns (uint256 token0, uint256 token1) {
    CollectedFees memory fees = _collectedFees[tokenId];
    return (fees.token0, fees.token1);
  }
```

# L3 - The user can unexpectedly burn token when collecting the fee.

The token [get burnt too early](https://github.com/ronin-chain/katana-v3-contracts/blob/03c80179e04f40d96f06c451ea494bb18f2a58fc/src/periphery/NonfungiblePositionManager.sol#L411)

In the new NonfungiblePositionManager.sol, the burn function is removed,

but when the position nft liquidty becomes 0, the token get burnt automatically.

```solidity
    // if there's no liquidity and no tokens owed, burn the position
    if (position.liquidity == 0) {
      delete _positions[params.tokenId];
      _burn(params.tokenId);
    }
```

This is a issue because user may not expect or not want to burn their nft token after collecting the fee.

User are force to add a tiny liquidity if they do not want to burn their token after collecting the fee.

the recommendation is

restore the burn function seperately

```solidity
function burn(uint256 tokenId) external payable override isAuthorizedForToken(tokenId) {
        Position storage position = _positions[tokenId];
        require(position.liquidity == 0 && position.tokensOwed0 == 0 && position.tokensOwed1 == 0, 'Not cleared');
        delete _positions[tokenId];
        _burn(tokenId);
    }
```
