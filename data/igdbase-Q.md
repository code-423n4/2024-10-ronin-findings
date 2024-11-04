

## QA-01 Lack of Descriptive Error Message in `require(token0 < token1)` in `createAndInitializePoolIfNecessary` Function

## Impact
The lack of a descriptive error message in the `require(token0 < token1)` statement reduces the code's clarity and ease of debugging. Without an explicit error message, users, developers, or auditors might struggle to quickly identify the cause of the failure when the condition is not met. While this does not present an immediate security threat, it can delay troubleshooting, potentially leading to extended downtime or confusion when trying to understand why a transaction reverted. In certain situations, where automation or external systems are interacting with this function, failure without a clear message might also impact user experience.

## Proof of Concept
The following code in the `PoolInitializer` contract contains a `require` statement without an error message:

```solidity
require(token0 < token1);
```

This code is found in the `createAndInitializePoolIfNecessary` function, where it ensures that `token0` and `token1` are ordered correctly before interacting with the pool. The lack of an error message could confuse developers or users who encounter a transaction revert but do not know why the condition failed.

Here is a direct reference to the code in GitHub:
- [GitHub Reference Link](https://github.com/ronin-chain/katana-v3-contracts/blob/03c80179e04f40d96f06c451ea494bb18f2a58fc/src/periphery/base/PoolInitializer.sol#L15-L35) 



## Recommended Mitigation Steps
To improve code clarity and debugging experience, add a descriptive error message to the `require` statement. For example:


### Recommended Mitigation Steps

Consider attaching some sort of access control to `execute()`.

## QA-02 Price Manipulation Vulnerability in `MixedRouteQuoterV1` Due to `slot0` Dependency

### Proof of Concept
In the [MixedRouteQuoterV1](https://github.com/ronin-chain/katana-v3-contracts/blob/03c80179e04f40d96f06c451ea494bb18f2a58fc/src/periphery/lens/MixedRouteQuoterV1.sol) contract, functions like `quoteExactInputSingleV3` retrieve real-time prices from `slot0`:
```solidity
uint160 sqrtPriceX96 = pool.slot0();
```
An attacker can momentarily manipulate the `slot0` price, impacting the accuracy of these quotes. If off-chain systems rely on this skewed quote, it may lead to adverse outcomes, particularly in the event of quick reversions after manipulation.

## Impact
The `MixedRouteQuoterV1` contract relies on the `slot0` price of Katana V3 pools to calculate quotes. Although the contract is designed for off-chain use, it remains vulnerable to price manipulation in scenarios where `slot0` can be temporarily skewed (e.g., via flash loans or MEV bots). If off-chain processes or other systems rely on the manipulated quotes, it may result in mispricing or financial loss in subsequent interactions. 

## Recommended Mitigation Steps
1. **Use TWAP or Oracle Verification**: Use TWAPs or decentralized oracles to verify `slot0`-derived prices, ensuring the quotes are not based on temporary manipulations.
2. **Slippage/Deviation Checks**: Apply thresholds to detect significant price deviations, and revert if these limits are exceeded during off-chain validation.


## QA-03 Missing Finalization Status in Swap Event of KatanaV3Pool
## Proof of Concept
The `swap` function in the `KatanaV3Pool` contract performs liquidity swaps without emitting a finalized status in the `Swap` event. This means that once a swap completes, there is no way for external systems to know if the swap has reached a final price where trading can be deemed complete.

## Impact
The absence of a finalization status in the `Swap` event can lead to significant challenges in tracking the completion of swap transactions within the KatanaV3Pool. This oversight may hinder the ability of external analytics tools to accurately determine when swaps have concluded and when liquidity can be considered stable. Consequently, it can result in erroneous assumptions about the pool's state, affecting decision-making for users and automated trading systems.

### Affected Code
- [KatanaV3Pool Contract - Swap Function](https://github.com/ronin-chain/katana-v3-contracts/blob/03c80179e04f40d96f06c451ea494bb18f2a58fc/src/core/KatanaV3Pool.sol#L552-L744) 

The relevant section of the code does not include a flag indicating whether the swap has been finalized:

```solidity
emit Swap(msg.sender, recipient, amount0, amount1, state.sqrtPriceX96, state.liquidity, state.tick);
// Missing finalization status
```

The lack of a mechanism to track finalization can lead to confusion among users and automated systems, potentially causing them to act on stale or inaccurate information.


## Recommended Mitigation Steps
1. **Modify the `Swap` Event**: 
   - Add a boolean `finalized` field to the `Swap` event declaration to indicate whether the swap has reached its final state.

   ```solidity
   event Swap(
       address indexed sender,
       address indexed recipient,
       int256 amount0,
       int256 amount1,
       uint160 sqrtPriceX96,
       uint128 liquidity,
       int24 tick,
       bool finalized // Add this field
   );
   ```

2. **Set the Finalized Flag**:
   - Implement logic to determine if a swap is finalized based on the swap parameters (e.g., whether the price has reached a target level).

3. **Emit the Updated Event**:
   - Update the emit statement in the `swap` function to include the finalized status.

   ```solidity
   emit Swap(msg.sender, recipient, amount0, amount1, state.sqrtPriceX96, state.liquidity, state.tick, isFinalized);
   ```

## QA-04 Outdated solidity compiler versions are being used
Severity: Low Risk
## Description: 
The repository is using compiler versions that are less than 0.8.0 which is not recommended.
Newer versions incorporate enhanced security features, addressing vulnerabilities present in older releases. In the
specific case of pragma versions >= 0.8.0 arithmetic operations are inherently safe which will naturally decrease
the attack surface for this repository.
## Recommendation:
 Consider bumping the prag