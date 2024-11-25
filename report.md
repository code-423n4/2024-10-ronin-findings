---
sponsor: "Ronin"
slug: "2024-10-ronin"
date: "2024-11-25"
title: "Ronin"
findings: "https://github.com/code-423n4/2024-10-ronin-findings/issues"
contest: 454
---

# Overview

## About C4

Code4rena (C4) is an open organization consisting of security researchers, auditors, developers, and individuals with domain expertise in smart contracts.

A C4 audit is an event in which community participants, referred to as Wardens, review, audit, or analyze smart contract logic in exchange for a bounty provided by sponsoring projects.

During the audit outlined in this document, C4 conducted an analysis of the Ronin smart contract system written in Solidity. The audit took place between October 16 — October 30, 2024.

## Wardens

4 Wardens contributed reports to Ronin:

  1. [PolarizedLight](https://code4rena.com/@PolarizedLight) ([ChaseTheLight](https://code4rena.com/@ChaseTheLight) and [Auditor\_Nate](https://code4rena.com/@Auditor_Nate))
  2. [rbserver](https://code4rena.com/@rbserver)
  3. [K42](https://code4rena.com/@K42)

This audit was judged by [0xsomeone](https://code4rena.com/@0xsomeone).

Final report assembled by [thebrittfactor](https://twitter.com/brittfactorC4).

# Summary

The C4 analysis yielded 0 HIGH or MEDIUM risk vulnerabilities.

Additionally, C4 analysis included 3 reports detailing issues with a risk rating of LOW severity or non-critical. 

All of the issues presented here are linked back to their original finding.

# Scope

The code under review can be found within the [C4 Ronin repository](https://github.com/code-423n4/2024-10-ronin), and is composed of 37 smart contracts written in the Solidity programming language and includes 2637 lines of Solidity code.

# Severity Criteria

C4 assesses the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/non-critical.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

- Malicious Input Handling
- Escalation of privileges
- Arithmetic
- Gas use

For more information regarding the severity criteria referenced throughout the submission review process, please refer to the documentation provided on [the C4 website](https://code4rena.com), specifically our section on [Severity Categorization](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization).

# Low Risk and Non-Critical Issues

For this audit, 3 reports were submitted by wardens detailing low risk and non-critical issues. The [report highlighted below](https://github.com/code-423n4/2024-10-ronin-findings/issues/81) by **PolarizedLight** received the top score from the judge.

*The following wardens also submitted reports: [rbserver](https://github.com/code-423n4/2024-10-ronin-findings/issues/5) and [K42](https://github.com/code-423n4/2024-10-ronin-findings/issues/80).*

## [01] Use of Uniswap's `slot0` value in Quoter may lead to volatile estimates

The MixedRouteQuoterV1 contract uses Uniswap's `slot0` value to provide quotes for swap outcomes. While efficient, this approach may result in more volatile and potentially less accurate quotes compared to using time-weighted average prices (TWAP).

### Description

The contract retrieves the current price from the Uniswap pool's `slot0` storage, which represents the most recent price update. This method is fast and gas-efficient but can be subject to short-term price fluctuations and potential manipulation, especially in low liquidity situations. As a result, the quotes provided may not always reflect the most representative price for users looking to execute swaps.

[MixedRouteQuoterV1.sol#L62](https://github.com/ronin-chain/katana-v3-contracts/blob/03c80179e04f40d96f06c451ea494bb18f2a58fc/src/periphery/lens/MixedRouteQuoterV1.sol#L62)

```solidity
Contract: MixedRouteQuoterV1.sol
Line 62: (uint160 v3SqrtPriceX96After, int24 tickAfter,,,,,,) = pool.slot0();
```

### Impact

The use of `slot0` for quoting may lead to:
- More volatile quote results.
- Potential for less accurate estimates during periods of high volatility.
- Slightly increased susceptibility to short-term price manipulations.

However, as this is a quoter contract explicitly designed for off-chain use and quick estimates, the overall impact is low. Users are expected to understand that quotes are estimates and may change before trade execution.

### Recommended Mitigation

Consider implementing an optional TWAP-based quoting function for users who prefer more stable estimates.

## [02] `Payable` functions without `withdraw` mechanism

Multiple contracts in the system contain `payable` functions but lack a corresponding `withdraw` or `sweep` function, potentially leading to ETH being locked in the contract.

### Description

The AggregateRouter, V3Migrator, and NonfungiblePositionManager contracts all include `payable` functions that allow them to receive ETH. However, these contracts do not implement a dedicated `withdraw` function that would allow for the recovery of any ETH that might accidentally accumulate in the contract.

While these contracts are designed to handle ETH as part of their normal operations (typically forwarding it to other contracts or refunding users), the absence of a `withdraw` function means there's no direct mechanism to retrieve ETH if it becomes stuck due to unforeseen circumstances or edge cases.

### Code
- AggregateRouter: `execute` function.
- V3Migrator: `receive` function and `migrate` function.
- NonfungiblePositionManager: `mint`, `increaseLiquidity`, `decreaseLiquidity`, and `collect` functions.

### Impact

The impact of this issue is considered low because:
1. The contracts are not designed to hold ETH long-term, reducing the risk of large-scale fund lock-up.
2. Existing mechanisms (like ETH refunds in V3Migrator) mitigate some of the risks.
3. Any ETH accumulation is likely to be minimal, resulting from edge cases or rounding errors rather than core functionality issues.
4. The primary operations of the contracts are not affected by this issue.

### Recommended Mitigation

Implement a `withdraw` function in each contract that allows an authorized address (e.g., the contract owner or governance) to withdraw any ETH that might accumulate. For example:

```solidity
address public governance;

function withdrawETH(address recipient, uint256 amount) external {
    require(msg.sender == governance, "Only governance can withdraw");
    payable(recipient).transfer(amount);
}
```

While the lack of a `withdraw` function in these contracts presents a potential for ETH to be locked, the low likelihood of significant ETH accumulation and the contracts' design to handle ETH transiently rather than store it long-term classify this as a low severity issue that can be addressed to improve the contracts' robustness and adhere to best practices.

## [03] Lack of standard initialization protection in key contracts

KatanaV3Pool, KatanaV3Factory, and NonfungiblePositionManager implement custom initialization functions without using standard initialization protection mechanisms like OpenZeppelin's `Initializable` contract.

### Description

The contracts use custom checks to prevent multiple initializations, such as checking if certain state variables are set to their default values. While these checks do provide some protection against multiple initializations, they don't follow the widely accepted standard of using an `initializer` modifier. 

### Code

1. KatanaV3Pool.sol:
```solidity
function initialize(uint160 sqrtPriceX96) external override {
  require(slot0.sqrtPriceX96 == 0, "AI");
  // ... initialization logic ...
}
```

2. KatanaV3Factory.sol:
```solidity
function initialize(address beacon_, address owner_, address treasury_) external {
  require(beacon == address(0), "KatanaV3Factory: ALREADY_INITIALIZED");
  // ... initialization logic ...
}
```

3. NonfungiblePositionManager.sol:
```solidity
function initialize() external {
  require(_nextId == 0, "Already initialized");
  // ... initialization logic ...
}
```

### Impact

The current implementation, while functional, deviates from best practices This could potentially lead to:
1. Increased difficulty in code review and auditing processes.
2. Possible oversights in future upgrades or integrations.
3. Slightly higher gas costs due to custom checks instead of optimized standard implementations.

### Recommended Mitigations

1. Implement OpenZeppelin's `Initializable` contract and use the `initializer` modifier for all initialization functions.
2. Add explicit access control to the initialization functions to ensure only authorized accounts can initialize the contracts.
3. Consider using a proxy pattern with initializer functions if upgradability is a requirement.

While the current initialization checks provide basic protection against multiple initializations, adopting standardized initialization patterns would enhance the contracts' security, readability, and maintainability.

## [04] `tokenURI()` lacks explicit token existence validation

The `tokenURI()` function in NonfungibleTokenPositionDescriptor contract does not explicitly validate token existence before generating and returning metadata, which violates EIP-721 standard requirements.

### Description

The NonfungibleTokenPositionDescriptor contract implements a `tokenURI()` function that generates metadata for NFT positions. However, it fails to explicitly verify if the queried token exists before attempting to retrieve its position data and generate the URI. While the function does call `positionManager.positions(tokenId)` which may revert for invalid tokens, the EIP-721 standard specifically requires that `tokenURI()` must verify token existence and revert for invalid tokens. Relying on implicit validation through the positions call does not provide the clear validation required by the standard.

`NonfungibleTokenPositionDescriptor.sol#L46-L86`:

```solidity
function tokenURI(INonfungiblePositionManager positionManager, uint256 tokenId)
    external
    view
    override
    returns (string memory)
{
    // Missing token existence check
    (,, address token0, address token1, uint24 fee, int24 tickLower, int24 tickUpper,,,,,) =
      positionManager.positions(tokenId);
    // ...
}
```

### Impact

- Violates EIP-721 standard requirements for explicit token validation.
- Could potentially return metadata for non-existent tokens if `positions()` don't properly validate.
- May cause integration issues with systems expecting strict EIP-721 compliance.
- Relies on implicit rather than explicit validation patterns.

### Recommended Mitigation

Add an explicit token existence check using the IERC721 `ownerOf()` function before processing the token metadata.

```solidity
function tokenURI(INonfungiblePositionManager positionManager, uint256 tokenId)
    external
    view
    override
    returns (string memory)
{
    require(positionManager.ownerOf(tokenId) != address(0), "URI query for nonexistent token");
    
    (,, address token0, address token1, uint24 fee, int24 tickLower, int24 tickUpper,,,,,) =
      positionManager.positions(tokenId);
    // ... rest of the function
}
```

While the current implementation may work in practice through implicit validation, the lack of explicit token existence checking represents a deviation from EIP-721 standards that should be addressed through proper validation using `ownerOf()`.

## [05] Use of deprecated `safeApprove` function in V3Migrator contract

The V3Migrator contract uses the deprecated `safeApprove` function from the TransferHelper library in multiple instances. This function has been superseded by more secure alternatives `safeIncreaseAllowance` and `safeDecreaseAllowance`.

### Description

The contract uses `safeApprove` to manage token approvals during the migration process from V2 to V3 pools. While functional, this method is deprecated due to potential issues with repeated approvals and is not recommended for new implementations. The main concern is that some tokens (like USDT) may revert on a second approval if the current allowance is not zero.

```solidity
// In migrate() function:
TransferHelper.safeApprove(params.token0, nonfungiblePositionManager, amount0V2ToMigrate);
TransferHelper.safeApprove(params.token1, nonfungiblePositionManager, amount1V2ToMigrate);

// In refund logic:
TransferHelper.safeApprove(params.token0, nonfungiblePositionManager, 0);
TransferHelper.safeApprove(params.token1, nonfungiblePositionManager, 0);
```

### Impact

While the current implementation works, it uses a deprecated pattern that could potentially cause issues with certain tokens that have strict approval requirements. This could lead to failed transactions in edge cases or require additional gas consumption.

### Recommended Mitigations

1. Replace `safeApprove` with `safeIncreaseAllowance` when setting initial approvals:

```solidity
TransferHelper.safeIncreaseAllowance(params.token0, nonfungiblePositionManager, amount0V2ToMigrate);
TransferHelper.safeIncreaseAllowance(params.token1, nonfungiblePositionManager, amount1V2ToMigrate);
```

2. Use `safeDecreaseAllowance` when reducing approvals to zero:

```solidity
TransferHelper.safeDecreaseAllowance(params.token0, nonfungiblePositionManager, amount0V2ToMigrate);
TransferHelper.safeDecreaseAllowance(params.token1, nonfungiblePositionManager, amount1V2ToMigrate);
```

The V3Migrator contract should update its approval mechanism from the deprecated `safeApprove` to the more secure and standardized `safeIncreaseAllowance` and `safeDecreaseAllowance` functions to ensure long-term compatibility and optimal security with all ERC20 tokens.

## [06] Unbounded loop in `initialize` function could lead to failed deployments

The `initialize` function in KatanaGovernance contains an unbounded loop that processes all existing pairs, performing multiple external calls and storage operations per iteration. This design can lead to excessive gas consumption that could exceed block gas limits on certain chains.

### Description

The `initialize` function iterates through all existing pairs to set permissions for their tokens. For each pair, it:
1. Makes an external call to retrieve the pair address.
2. Makes two more external calls to get token addresses.
3. Performs multiple storage operations to set permissions.
4. Updates the `EnumerableSet` storage.

The gas cost scales linearly with the number of pairs, and there is no upper bound or mechanism to handle partial initialization. This poses a risk on chains with lower block gas limits or when there are many pairs to process.

```solidity
function initialize(address admin, address factory) external initializer {
    _setFactory(factory);
    __Ownable_init_unchained(admin);

    IKatanaV2Pair pair;
    uint40 until = AUTHORIZED;
    bool[] memory statusesPlaceHolder;
    address[] memory allowedPlaceHolder;
    uint256 length = IKatanaV2Factory(factory).allPairsLength();

    for (uint256 i; i < length; ++i) {
      pair = IKatanaV2Pair(IKatanaV2Factory(factory).allPairs(i));
      _setPermission(pair.token0(), until, allowedPlaceHolder, statusesPlaceHolder);
      _setPermission(pair.token1(), until, allowedPlaceHolder, statusesPlaceHolder);
    }
}
```

### Impact

- Failed contract deployments if gas limit is exceeded.
- Inconsistent deployment behavior across different chains.
- Could block protocol deployment on chains with lower gas limits.
- No fallback mechanism if initialization fails.

### Recommended Mitigations

1. Implement Batched Initialization

```solidity
uint256 public lastInitializedIndex;
bool public initializationComplete;

function initialize(address admin, address factory) external initializer {
    _setFactory(factory);
    __Ownable_init_unchained(admin);
    lastInitializedIndex = 0;
    initializationComplete = false;
}

function continueInitialization(uint256 batchSize) external onlyOwner {
    require(!initializationComplete, "Already initialized");
    uint256 length = IKatanaV2Factory(factory).allPairsLength();
    uint256 endIndex = Math.min(lastInitializedIndex + batchSize, length);
    
    for (uint256 i = lastInitializedIndex; i < endIndex; ++i) {
        IKatanaV2Pair pair = IKatanaV2Pair(IKatanaV2Factory(factory).allPairs(i));
        _setPermission(pair.token0(), until, allowedPlaceHolder, statusesPlaceHolder);
        _setPermission(pair.token1(), until, allowedPlaceHolder, statusesPlaceHolder);
    }
    
    lastInitializedIndex = endIndex;
    if (lastInitializedIndex == length) {
        initializationComplete = true;
    }
}
```

2. Implement Lazy Initialization
    - Instead of setting all permissions at deployment, initialize permissions when pairs are first accessed.
    - Add a function to pre-initialize specific pairs when needed.

3. Add Gas Limit Protection
    - Implement a maximum iteration count based on estimated gas costs.
    - Add mechanisms to track and resume partial initialization.
    - Include chain-specific gas limit considerations.

The unbounded initialization loop presents a significant deployment risk that could prevent successful contract deployment on chains with lower gas limits or when processing a large number of pairs, requiring immediate architectural changes to ensure reliable deployment across different blockchain environments.

## [07] Unsafe array index arithmetic in Swap Router logic

The V2SwapRouter contract performs direct arithmetic operations within array access indexes during token swap operations, which could potentially lead to out-of-bounds access or unexpected behavior.

### Description

The `_v2Swap` function performs direct arithmetic within array indices when accessing elements of the path array during token swaps. Specifically, when determining the next pair in the swap path, the code performs unchecked arithmetic operation `i + 2` directly within the array access:

```solidity
(nextPair, token0) = i < penultimatePairIndex
    ? KatanaV2Library.pairAndToken0For(KATANA_V2_FACTORY, KATANA_V2_PAIR_INIT_CODE_HASH, output, path[i + 2])
    : (recipient, address(0));
```

While there is a basic length check at the start of the function (`if (path.length < 2) revert V2InvalidPath()`), the subsequent array access using `i + 2` occurs within an unchecked block and could potentially access elements beyond the array bounds.

### Code

- File: V2SwapRouter.sol
- Line numbers: 39-41

```solidity
(nextPair, token0) = i < penultimatePairIndex
    ? KatanaV2Library.pairAndToken0For(KATANA_V2_FACTORY, KATANA_V2_PAIR_INIT_CODE_HASH, output, path[i + 2])
    : (recipient, address(0));
```

### Impact

- Potential out-of-bounds array access in certain edge cases.
- Possible revert of swap operations if path array boundaries are not properly validated.
- Risk of unexpected behavior in multi-hop swaps when path array length is close to the accessed index.

### Recommended Mitigations

1. Pre-calculate and validate array indices before access:

```solidity
uint256 nextPathIndex = i + 2;
require(nextPathIndex < path.length, "Invalid path index");
(nextPair, token0) = i < penultimatePairIndex
    ? KatanaV2Library.pairAndToken0For(KATANA_V2_FACTORY, KATANA_V2_PAIR_INIT_CODE_HASH, output, path[nextPathIndex])
    : (recipient, address(0));
```

2. Add explicit boundary checks before the loop:

```solidity
require(path.length >= 3, "Path too short for multi-hop"); // Since we access i+2
```

The direct arithmetic operation within array access `path[i + 2]` in the swap router's core logic presents a potential security risk that should be addressed through proper index validation and bounds checking to ensure safe multi-hop swap execution.

## [08] Potential for improved safety in token minting process

The NonfungiblePositionManager contract uses the `_mint` function instead of `_safeMint` when creating new position tokens. While not critical in this specific context, using `_safeMint` could provide an additional layer of safety.

### Description

The contract uses `_mint` to create new ERC721 tokens representing Katana V3 liquidity positions. While `_mint` is sufficient in many cases, `_safeMint` offers additional checks that can prevent tokens from being minted to addresses unable to handle ERC721 tokens.

### Code

- File: NonfungiblePositionManager.sol
- Line: 282 (approximate, based on the provided snippet)

```solidity
_mint(params.recipient, (tokenId = _nextId++));
```

### Impact

Low. The specialized nature of this contract and its controlled minting process mitigate most risks associated with using `_mint`. However, using `_safeMint` could prevent potential edge cases where tokens are minted to incompatible addresses.

### Recommended Mitigation

Replace the current `_mint` call with `_safeMint`:

```solidity
_safeMint(params.recipient, (tokenId = _nextId++));
```

This change would add an extra layer of safety by checking if the recipient is a contract and, if so, ensuring it can handle ERC721 tokens.

While the use of `_mint` in the NonfungiblePositionManager is not a critical issue due to the contract's specialized nature, implementing `_safeMint` would align with best practices and provide an additional safety check in the token minting process.

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-10-ronin-findings/issues/81#issuecomment-2490882687):**
 > I believe that [02] is an item that has questionable validity due to the usage of those native funds supplied and due to the execute function being part of a multi-call that can use those funds.

***

## [`LiquidityManagement.katanaV3MintCallback()` is subject to address collision attack, allowing an attacker to steal funds from users who give approvals to the `NonfungiblePositionManager`](https://github.com/code-423n4/2024-10-ronin-findings/issues/32) 

*Submitted by chaduke, also found by [1337web3](https://github.com/code-423n4/2024-10-ronin-findings/issues/66), [4B](https://github.com/code-423n4/2024-10-ronin-findings/issues/58), [bareli](https://github.com/code-423n4/2024-10-ronin-findings/issues/51) and [Stryder](https://github.com/code-423n4/2024-10-ronin-findings/issues/42).*

*Note: At the sponsor's request, this downgraded issue has been included in this report.*

### Lines of Code

`NonfungiblePositionManager.sol#L25-L31`

### Proof of Concept

The `LiquidityManagement.katanaV3MintCallback()` function is expected to be called only by a valid pool. However, if an attacker can craft an address (let's call it B) using the `create2` opcode, which passes as a pool address, the attacker can exploit this to steal user approvals and funds. Many users, for convenience, grant maximum approvals to the `NonfungiblePositionManager`, which leaves them vulnerable. The attacker can use their controlled contract at address B to steal funds by calling `LiquidityManagement.katanaV3MintCallback()` as follows:
 
1. Find the address B which can pass a pool address, 
2. Deploy a contract using `create2` on B, say contractB
3. Call `katanaV3MintCallback` with appropriate values for `amount0Owed`, `amount1Owed` and make sure `data.payer` is the address of the user we like to steal (we can check the transaction history to identify such victims who gave approvals to the `NonfungiblePositionManager`). 

```javascript
  function katanaV3MintCallback(uint256 amount0Owed, uint256 amount1Owed, bytes calldata data) external override {
    MintCallbackData memory decoded = abi.decode(data, (MintCallbackData));
    CallbackValidation.verifyCallback(factory, decoded.poolKey);

    if (amount0Owed > 0) pay(decoded.poolKey.token0, decoded.payer, msg.sender, amount0Owed);
    if (amount1Owed > 0) pay(decoded.poolKey.token1, decoded.payer, msg.sender, amount1Owed);
  }
``` 

In the following we show how such B can be found. First, let's see how the pool verification works.

```javascript
CallbackValidation.verifyCallback(factory, decoded.poolKey):


 function verifyCallback(address factory, PoolAddress.PoolKey memory poolKey)
    internal
    view
    returns (IKatanaV3Pool pool)
  {
    pool = IKatanaV3Pool(PoolAddress.computeAddress(factory, poolKey));
    require(msg.sender == address(pool));
  }

 function computeAddress(address factory, PoolKey memory key) internal pure returns (address pool) {
    require(key.token0 < key.token1);
    pool = address(
      uint256(
        keccak256(
          abi.encodePacked(
            hex"ff", factory, keccak256(abi.encode(key.token0, key.token1, key.fee)), POOL_PROXY_INIT_CODE_HASH
          )
        )
      )
    );
  }
```

The verification does not check whether the caller (`msg.sender`) is a pool deployed by the factory or not. It only checks that caller address matches an address that can be computed by `computeAddress()` where `key.fee` can be searched in a brute-force fashion, as we show below. If the attacker can find a `key.fee` such that the computed address happens to be controlled by the attacker, bingo, that address can be used to steal funds.  

Note that as the computation of the `Create2` address is done by truncating a 256 bit `keccak256` hash to 160 bits, meaning `2^96` possible hashes will be mapped to the same address!

We need to find a collision between two lists: 
1. Brute-force different `key.fee`, function `computeAddress` will produce a list of addresses. 
2. With the attacker's factory contract, brute force various `salt` with `create2` will produce another list of addresses. 

Once we find a collision B between these two lists, the attacker can deploy a contract to address B, which passes the pool verification, and then proceed to exploit approvals and steal funds as described above.

Several similar collision attacks have been reported and rewarded: 

1. [Napier audit](https://github.com/sherlock-audit/2024-01-napier-judging/issues/111)
2. [Arcadia audit](https://github.com/sherlock-audit/2023-12-arcadia-judging/issues/59)
3. [EIP-3607](https://eips.ethereum.org/EIPS/eip-3607), which rationale is this exact attack. The EIP is in final state.

The feasibility and cost of the attack has been discussed in above reports. 

### Recommended Mitigation Steps

The factory should keep track of all the pools that it has deployed, the callback function can call factory to check whether `msg.sender` is one of those pools. 

### Assessed type

Invalid Validation

**[thaixuandang (Ronin) commented](https://github.com/code-423n4/2024-10-ronin-findings/issues/32#issuecomment-2456777027):**
> The likelihood of generating such addresses is extremely low—it’s as difficult as trying to generate Satoshi’s private key. If this could be exploited, Uniswap would have been compromised long ago.

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-10-ronin-findings/issues/32#issuecomment-2468861045):**
> The Warden attempts to identify an address collision-based vulnerability based on the `create2` pattern. This "vulnerability" is applicable to Uniswap V3 and many of its forks, and would result in millions of paid-out bounties if it were truly considered a medium vulnerability.
> 
> As the first Sherlock judgment outlines, the memory capacity needs **beyond the computational power needs are impossible right now** to even attempt this attack. I do not believe these submissions are made in good faith as medium ones, and I consider the outlined issues to be valid albeit of QA (L) severity.
> 
> I would like to correct the Sponsor in the sense that the complexity **is not the same as finding a single address** as a list of addresses can be generated via brute-forcing.

**[khangvv (Ronin) commented](https://github.com/code-423n4/2024-10-ronin-findings/issues/32#issuecomment-2469838515):**
> @0xsomeone, we are addressing this issue in two PRs: 
> - https://github.com/ronin-chain/katana-v3-contracts/pull/34 
> - https://github.com/ronin-chain/katana-operation-contracts/pull/13 

**[0xsomeone (judge) commented](https://github.com/code-423n4/2024-10-ronin-findings/issues/32#issuecomment-2480737010)**
> @khangvv, I have reviewed the associated PRs and can confirm that the reported issue has been remediated in both the `katana-operation-contracts` and `katana-v3-contracts` repositories based on the audit's scope. To note, I advise any other infrastructure in use by the Ronin Chain team that was not in the scope of the audit to be updated accordingly if it employs similar checks as a best practice.

***

# Disclosures

C4 is an open organization governed by participants in the community.

C4 audits incentivize the discovery of exploits, vulnerabilities, and bugs in smart contracts. Security researchers are rewarded at an increasing rate for finding higher-risk issues. Audit submissions are judged by a knowledgeable security researcher and solidity developer and disclosed to sponsoring developers. C4 does not conduct formal verification regarding the provided code but instead provides final verification.

C4 does not provide any guarantee or warranty regarding the security of this project. All smart contract software should be used at the sole risk and responsibility of users.
