## QA REPORT

|      | Issue                                                                                                                                                                                                                                   |
| ---- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [01] | `KatanaV3Factory.createPool` and `V3Migrator.createAndInitializePoolIfNecessary` functions can be DOS'ed                                                                                                                                |
| [02] | `IKatanaGovernance(governance).isAuthorized(tokens, msg.sender)` requirement for creating and initializing corresponding pool can be bypassed and become ineffective                                                                    |
| [03] | Using `_v2Factory.allowedAll` function to control whether an account can perform V3 protocol's swaps can enable accounts unauthorized by V3 protocol to perform corresponding swaps of V3 protocol though they should not be allowed to |
| [04] | Signature and corresponding hash for `PERMIT2.permit` functions that can be called by `Dispatcher.dispatch` function do not include `version` and `salt`, which can cause signature replay issue                                        |
| [05] | Using `SignatureVerification.verify` function that supports EIP-2098 increases attack surface                                                                                                                                           |
| [06] | `UniswapV2Library.getAmountIn` function includes `amountOut > 0` requirement but `KatanaV2Library.getAmountIn` function does not                                                                                                        |
| [07] | Solmate's `SafeTransferLib` used by `Payments` contract does not check if corresponding token has code or not                                                                                                                           |
| [08] | `Dispatcher.dispatch` function call to further call `permit2TransferFrom` functions can revert                                                                                                                                          |
| [09] | Calling `Payments.pay` function with `Constants.CONTRACT_BALANCE` as `value` input when `token` is ETH can revert and waste gas                                                                                                         |
| [10] | `KatanaV3Factory.initialize` function can be frontrun                                                                                                                                                                                   |
| [11] | Missing `address(0)` checks in `V3Migrator` and `PeripheryImmutableState` contracts' constructors                                                                                                                                       |
| [12] | Unlocked Solidity version in contracts                                                                                                                                                                                                  |

## [01] `KatanaV3Factory.createPool` and `V3Migrator.createAndInitializePoolIfNecessary` functions can be DOS'ed

### Description
The `KatanaV3Factory.createPool` function should only allow the trusted position manager to create a pool because it executes `require(msg.sender == IKatanaGovernance(owner).getPositionManager(), "KatanaV3Factory: INVALID_POSITION_MANAGER")`. However, since the `salt`, which encodes the given `tokenA`, `tokenB`, and `fee`, and `creationCode` for calling the `Create2.deploy` function, which would be called by the `KatanaV3PoolDeployer.deploy` function, are known, anyone can directly call the `Create2.deploy` function with the same `salt` and `creationCode` to create the pool for such `tokenA`, `tokenB`, and `fee`. This bypasses the `msg.sender == IKatanaGovernance(owner).getPositionManager()` requirement, and calling the `KatanaV3Factory.createPool` function for the same `tokenA`, `tokenB`, and `fee` after such `Create2.deploy` function call will always revert since the corresponding pool address is already occupied. Therefore, the `PoolCreated` event cannot be emitted, which can disrupt the system that consumes such event.

https://github.com/ronin-chain/katana-v3-contracts/blob/3ffd56300ced6ec42c5dcbe28d4420c5011e49e2/src/core/KatanaV3Factory.sol#L77-L91
```solidity
  function createPool(address tokenA, address tokenB, uint24 fee) external override returns (address pool) {
@>  require(msg.sender == IKatanaGovernance(owner).getPositionManager(), "KatanaV3Factory: INVALID_POSITION_MANAGER");

    require(tokenA != tokenB);
    (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
    require(token0 != address(0));
    int24 tickSpacing = feeAmountTickSpacing[fee];
    require(tickSpacing != 0);
    require(getPool[token0][token1][fee] == address(0));
@>  pool = deploy(address(this), token0, token1, fee, tickSpacing);
    getPool[token0][token1][fee] = pool;
    // populate mapping in the reverse direction, deliberate choice to avoid the cost of comparing addresses
    getPool[token1][token0][fee] = pool;
    emit PoolCreated(token0, token1, fee, tickSpacing, pool);
  }
```

https://github.com/ronin-chain/katana-v3-contracts/blob/f2a69057f04bac0372c3419168ba75fafd0e09eb/src/core/KatanaV3PoolDeployer.sol#L31-L40
```solidity
  function deploy(address factory, address token0, address token1, uint24 fee, int24 tickSpacing)
    internal
    returns (address pool)
  {
    parameters = Parameters({ factory: factory, token0: token0, token1: token1, fee: fee, tickSpacing: tickSpacing });
@>  bytes memory creationCode = IKatanaV3PoolBeaconImmutables(beacon).POOL_PROXY_INIT_CODE();
@>  bytes32 salt = keccak256(abi.encode(token0, token1, fee));
@>  pool = Create2.deploy(0, salt, creationCode);
    delete parameters;
  }
```

Moreover, since such `KatanaV3Factory.createPool` function call reverts in this case, the corresponding `getPool` state variable can never be set. This DOSes the `V3Migrator.createAndInitializePoolIfNecessary` function because the further-called `PoolInitializer.createAndInitializePoolIfNecessary` function would always consider the pool as not created when executing `IKatanaV3Factory(factory).getPool(token0, token1, fee)` and then executes `IKatanaV3Factory(factory).createPool(token0, token1, fee)` that reverts.

https://github.com/ronin-chain/katana-v3-contracts/blob/b841b153c44e9f30a4971610c2543c4c0a8321ce/src/periphery/V3Migrator.sol#L99-L109
```solidity
  function createAndInitializePoolIfNecessary(address token0, address token1, uint24 fee, uint160 sqrtPriceX96)
    external
    payable
    override
    returns (address pool)
  {
    AuthorizationLib.checkPair(governance, token0, token1);
@>  return INonfungiblePositionManager(nonfungiblePositionManager).createAndInitializePoolIfNecessary(
      token0, token1, fee, sqrtPriceX96
    );
  }
```

https://github.com/ronin-chain/katana-v3-contracts/blob/84b67dd5ffbdc27347ef53c0cd5857162e7a73c6/src/periphery/base/PoolInitializer.sol#L15-L35
```solidity
  function createAndInitializePoolIfNecessary(address token0, address token1, uint24 fee, uint160 sqrtPriceX96)
    external
    payable
    override
    returns (address pool)
  {
    AuthorizationLib.checkPair(governance, token0, token1);

    require(token0 < token1);
@>  pool = IKatanaV3Factory(factory).getPool(token0, token1, fee);

@>  if (pool == address(0)) {
@>    pool = IKatanaV3Factory(factory).createPool(token0, token1, fee);
      IKatanaV3Pool(pool).initialize(sqrtPriceX96);
    } else {
      (uint160 sqrtPriceX96Existing,,,,,,,) = IKatanaV3Pool(pool).slot0();
      if (sqrtPriceX96Existing == 0) {
        IKatanaV3Pool(pool).initialize(sqrtPriceX96);
      }
    }
  }
```

### Recommended Mitigation
The `KatanaV3PoolDeployer.deploy` function can be updated to additionally encode a combination of an increasing nonce and `block.timestamp` as a part of the `salt` for calling the `Create2.deploy` function.

## [02] `IKatanaGovernance(governance).isAuthorized(tokens, msg.sender)` requirement for creating and initializing corresponding pool can be bypassed and become ineffective

### Description
Both the `V3Migrator.createAndInitializePoolIfNecessary` and `PoolInitializer.createAndInitializePoolIfNecessary` functions call the `AuthorizationLib.checkPair` function, which executes `require(IKatanaGovernance(governance).isAuthorized(tokens, msg.sender), "UA")` to verify if the `msg.sender` is authorized by the governance for creating and/or initializing a pool for the corresponding tokens. Therefore, only the address authorized by the governance should be allowed to call these functions to create the corresponding pool if it is not created yet and/or initialize such pool if it has been created but not initialized.

https://github.com/ronin-chain/katana-v3-contracts/blob/b841b153c44e9f30a4971610c2543c4c0a8321ce/src/periphery/V3Migrator.sol#L99-L109
```solidity
  function createAndInitializePoolIfNecessary(address token0, address token1, uint24 fee, uint160 sqrtPriceX96)
    external
    payable
    override
    returns (address pool)
  {
@>  AuthorizationLib.checkPair(governance, token0, token1);
    return INonfungiblePositionManager(nonfungiblePositionManager).createAndInitializePoolIfNecessary(
      token0, token1, fee, sqrtPriceX96
    );
  }
```

https://github.com/ronin-chain/katana-v3-contracts/blob/84b67dd5ffbdc27347ef53c0cd5857162e7a73c6/src/periphery/base/PoolInitializer.sol#L15-L35
```solidity
  function createAndInitializePoolIfNecessary(address token0, address token1, uint24 fee, uint160 sqrtPriceX96)
    external
    payable
    override
    returns (address pool)
  {
@>  AuthorizationLib.checkPair(governance, token0, token1);

    require(token0 < token1);
    pool = IKatanaV3Factory(factory).getPool(token0, token1, fee);

    if (pool == address(0)) {
      pool = IKatanaV3Factory(factory).createPool(token0, token1, fee);
      IKatanaV3Pool(pool).initialize(sqrtPriceX96);
    } else {
      (uint160 sqrtPriceX96Existing,,,,,,,) = IKatanaV3Pool(pool).slot0();
      if (sqrtPriceX96Existing == 0) {
        IKatanaV3Pool(pool).initialize(sqrtPriceX96);
      }
    }
  }
```

https://github.com/ronin-chain/katana-v3-contracts/blob/f2a69057f04bac0372c3419168ba75fafd0e09eb/src/external/libraries/AuthorizationLib.sol#L7-L12
```solidity
  function checkPair(address governance, address token0, address token1) internal view {
    address[] memory tokens = new address[](2);
    tokens[0] = token0;
    tokens[1] = token1;
@>  require(IKatanaGovernance(governance).isAuthorized(tokens, msg.sender), "UA");
  }
```

However, the `IKatanaGovernance(governance).isAuthorized(tokens, msg.sender)` requirement for creating the corresponding pool can be bypassed because anyone can create a `salt` that encodes the corresponding tokens and fee and directly call the `Create2.deploy` function to deterministically deploy a pool for these tokens and fee similar to what the `KatanaV3PoolDeployer.deploy` function does.

https://github.com/ronin-chain/katana-v3-contracts/blob/f2a69057f04bac0372c3419168ba75fafd0e09eb/src/core/KatanaV3PoolDeployer.sol#L31-L40
```solidity
  function deploy(address factory, address token0, address token1, uint24 fee, int24 tickSpacing)
    internal
    returns (address pool)
  {
    parameters = Parameters({ factory: factory, token0: token0, token1: token1, fee: fee, tickSpacing: tickSpacing });
@>  bytes memory creationCode = IKatanaV3PoolBeaconImmutables(beacon).POOL_PROXY_INIT_CODE();
@>  bytes32 salt = keccak256(abi.encode(token0, token1, fee));
@>  pool = Create2.deploy(0, salt, creationCode);
    delete parameters;
  }
```

Moreover, the `IKatanaGovernance(governance).isAuthorized(tokens, msg.sender)` requirement for initializing the corresponding pool can also be bypassed since the `KatanaV3Pool.initialize` function has no access control and anyone can call this function to initialize any uninitialized pool that has been created and set its initial values, such as `slot0.sqrtPriceX96`.

As a result, the `IKatanaGovernance(governance).isAuthorized(tokens, msg.sender)` requirement for creating and initializing the corresponding pool that should be enforced for the `V3Migrator.createAndInitializePoolIfNecessary` and `PoolInitializer.createAndInitializePoolIfNecessary` functions can be bypassed and become ineffective, and addresses that are not authorized by the governance can create and/or initialize pools.

https://github.com/ronin-chain/katana-v3-contracts/blob/84b67dd5ffbdc27347ef53c0cd5857162e7a73c6/src/core/KatanaV3Pool.sol#L246-L267
```solidity
  function initialize(uint160 sqrtPriceX96) external override {
    require(slot0.sqrtPriceX96 == 0, "AI");

    int24 tick = TickMath.getTickAtSqrtRatio(sqrtPriceX96);

    (uint16 cardinality, uint16 cardinalityNext) = observations.initialize(_blockTimestamp());

    (uint8 feeProtocolNum, uint8 feeProtocolDen) = IKatanaV3Factory(factory).feeAmountProtocol(fee);

    slot0 = Slot0({
      sqrtPriceX96: sqrtPriceX96,
      tick: tick,
      observationIndex: 0,
      observationCardinality: cardinality,
      observationCardinalityNext: cardinalityNext,
      feeProtocolNum: feeProtocolNum,
      feeProtocolDen: feeProtocolDen,
      unlocked: true
    });

    emit Initialize(sqrtPriceX96, tick);
  }
```

### Recommended Mitigation
Since the pool creation process through the `NonfungiblePositionManager` and `KatanaV3Factory` contracts can only be triggered by the address authorized by the governance for the corresponding tokens, the pool created using this process needs to be unique. To ensure that such created pool is unique, the `KatanaV3PoolDeployer.deploy` function can be updated to encode a combination of an increasing nonce and `block.timestamp` in addition to the existing data for the `Create2.deploy` function's `salt` input. Moreover, the `KatanaV3Pool.initialize` function can be updated to be only callable by the `NonfungiblePositionManager` contract.

## [03] Using `_v2Factory.allowedAll` function to control whether an account can perform V3 protocol's swaps can enable accounts unauthorized by V3 protocol to perform corresponding swaps of V3 protocol though they should not be allowed to

### Description
When the `Dispatcher.dispatch` function is called for the `V3_SWAP_EXACT_IN` and `V3_SWAP_EXACT_OUT` commands, `checkAuthorizedV3Path(path)` is executed.

https://github.com/ronin-chain/katana-operation-contracts/blob/3dd0d8503aa4360e75a6acaddec3707c8581c188/src/aggregate-router/base/Dispatcher.sol#L28-L203
```solidity
  function dispatch(bytes1 commandType, bytes calldata inputs) internal returns (bool success, bytes memory output) {
    uint256 command = uint8(commandType & Commands.COMMAND_TYPE_MASK);

    success = true;

    // 0x00 <= command < 0x08
    if (command < Commands.FIRST_IF_BOUNDARY) {
      if (command == Commands.V3_SWAP_EXACT_IN) {
        // equivalent: abi.decode(inputs, (address, uint256, uint256, bytes, bool))
        address recipient;
        uint256 amountIn;
        uint256 amountOutMin;
        bool payerIsUser;
        assembly {
          recipient := calldataload(inputs.offset)
          amountIn := calldataload(add(inputs.offset, 0x20))
          amountOutMin := calldataload(add(inputs.offset, 0x40))
          // 0x60 offset is the path, decoded below
          payerIsUser := calldataload(add(inputs.offset, 0x80))
        }
        bytes calldata path = inputs.toBytes(3);
        address payer = payerIsUser ? lockedBy : address(this);
        v3SwapExactInput(map(recipient), amountIn, amountOutMin, path, payer);
@>      checkAuthorizedV3Path(path); // place the check here to avoid stack too deep error
      } else if (command == Commands.V3_SWAP_EXACT_OUT) {
        // equivalent: abi.decode(inputs, (address, uint256, uint256, bytes, bool))
        address recipient;
        uint256 amountOut;
        uint256 amountInMax;
        bool payerIsUser;
        assembly {
          recipient := calldataload(inputs.offset)
          amountOut := calldataload(add(inputs.offset, 0x20))
          amountInMax := calldataload(add(inputs.offset, 0x40))
          // 0x60 offset is the path, decoded below
          payerIsUser := calldataload(add(inputs.offset, 0x80))
        }
        bytes calldata path = inputs.toBytes(3);
        address payer = payerIsUser ? lockedBy : address(this);
        v3SwapExactOutput(map(recipient), amountOut, amountInMax, path, payer);
@>      checkAuthorizedV3Path(path);
      }
      ...
    } else {
      ...
    }
  }
```

Calling the `V3SwapRouter.checkAuthorizedV3Path` function would not revert if `IKatanaGovernance(KATANA_GOVERNANCE).isAuthorized(tokens, msg.sender)` returns true.

https://github.com/ronin-chain/katana-operation-contracts/blob/3dd0d8503aa4360e75a6acaddec3707c8581c188/src/aggregate-router/modules/katana/v3/V3SwapRouter.sol#L143-L151
```solidity
  function checkAuthorizedV3Path(bytes calldata path) internal view {
    uint256 length = path.length / Constants.NEXT_V3_POOL_OFFSET + 1;
    address[] memory tokens = new address[](length);
    for (uint256 i; i < length; ++i) {
      tokens[i] = path.decodeFirstToken();
      if (i + 1 < length) path = path.skipToken();
    }
@>  if (!IKatanaGovernance(KATANA_GOVERNANCE).isAuthorized(tokens, msg.sender)) revert V3UnauthorizedSwap();
  }
```

The `KatanaGovernance.isAuthorized` function would return true when the `KatanaGovernance._isSkipped` function returns true.

https://github.com/ronin-chain/katana-operation-contracts/blob/3f4ae379965709e8729bb4bce6397d00d23a5012/src/governance/KatanaGovernance.sol#L249-L267
```solidity
  function isAuthorized(address token, address account) public view returns (bool authorized) {
    if (_isSkipped(account)) return true;

    authorized = _isAuthorized(_permission[token], account);
  }
  ...
  function isAuthorized(address[] memory tokens, address account) public view returns (bool authorized) {
    if (_isSkipped(account)) return true;

    uint256 length = tokens.length;
    for (uint256 i; i < length; ++i) {
      if (!_isAuthorized(_permission[tokens[i]], account)) return false;
    }

    return true;
  }
```

The `KatanaGovernance._isSkipped` function would return true when the `KatanaGovernance.allowedAll` function returns true.

https://github.com/ronin-chain/katana-operation-contracts/blob/3f4ae379965709e8729bb4bce6397d00d23a5012/src/governance/KatanaGovernance.sol#L386-L388
```solidity
  function _isSkipped(address account) internal view returns (bool) {
    return isAllowedActor[account] || allowedAll() || account == owner();
  }
```

The `KatanaGovernance.allowedAll` function would return true when the `_v2Factory.allowedAll` function returns true. However, using the `_v2Factory.allowedAll` function to control whether an account can perform the V3 protocol's swaps can be problematic. For instance, when the V2 protocol allows all for swaps in which the `_v2Factory.allowedAll` function returns true but the V3 protocol intends to only authorize certain accounts to swap for certain paths, `IKatanaGovernance(KATANA_GOVERNANCE).isAuthorized(tokens, msg.sender)` would return true when the `V3SwapRouter.checkAuthorizedV3Path` function is called even if such `msg.sender` is not authorized for the corresponding swap of the V3 protocol. As a result, unauthorized accounts are able to perform the V3 protocol's swaps even though they should not be allowed to.

https://github.com/ronin-chain/katana-operation-contracts/blob/3f4ae379965709e8729bb4bce6397d00d23a5012/src/governance/KatanaGovernance.sol#L332-L334
```solidity
  function allowedAll() public view returns (bool) {
    return _v2Factory.allowedAll();
  }
```

### Recommended Mitigation
The V3 protocol's factory can be updated to include its own `allowedAll` state variable. When it is true, all accounts can perform the V3 protocol's swaps. When it is false, the corresponding account needs to be checked for whether it can perform the corresponding swaps of the V3 protocol.

## [04] Signature and corresponding hash for `PERMIT2.permit` functions that can be called by `Dispatcher.dispatch` function do not include `version` and `salt`, which can cause signature replay issue

### Description
According to https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-domainseparator, `domainSeparator` should equal `hashStruct(eip712Domain)`, where the `eip712Domain` could include `version` that is `the current major version of the signing domain` and `salt` that is `an disambiguating salt for the protocol`. Yet, the `eip712Domain` used by this protocol does not include such `version` and `salt` as shown by `EIP712._TYPE_HASH`.

https://github.com/ronin-chain/permit2x/blob/cfb7a4d9b5145886422f1076ebdb5a03d6f86778/src/EIP712.sol#L14-L15
```solidity
    bytes32 private constant _TYPE_HASH =
        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
```

https://github.com/ronin-chain/permit2x/blob/cfb7a4d9b5145886422f1076ebdb5a03d6f86778/src/EIP712.sol#L36-L38
```solidity
    function _hashTypedData(bytes32 dataHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), dataHash));
    }
```

Hence, when the `Dispatcher.dispatch` function calls the `PERMIT2.permit` functions, the provided signature and the corresponding hash would not include such `version` and `salt`. As a result, after the protocol gets an upgrade, the signature that should only be used for an old version of the protocol can be verified and replayed for the new version of the protocol though it should not be allowed to.

https://github.com/ronin-chain/katana-operation-contracts/blob/3dd0d8503aa4360e75a6acaddec3707c8581c188/src/aggregate-router/base/Dispatcher.sol#L28-L203
```solidity
  function dispatch(bytes1 commandType, bytes calldata inputs) internal returns (bool success, bytes memory output) {
    ...
    if (command < Commands.FIRST_IF_BOUNDARY) {
      ...
      } else if (command == Commands.PERMIT2_PERMIT_BATCH) {
        (IAllowanceTransfer.PermitBatch memory permitBatch,) =
          abi.decode(inputs, (IAllowanceTransfer.PermitBatch, bytes));
        bytes calldata data = inputs.toBytes(1);
        PERMIT2.permit(lockedBy, permitBatch, data);
      }
      ...
    } else {
      ...
      } else if (command == Commands.PERMIT2_PERMIT) {
        // equivalent: abi.decode(inputs, (IAllowanceTransfer.PermitSingle, bytes))
        IAllowanceTransfer.PermitSingle calldata permitSingle;
        assembly {
          permitSingle := inputs.offset
        }
        bytes calldata data = inputs.toBytes(6); // PermitSingle takes first 6 slots (0..5)
        PERMIT2.permit(lockedBy, permitSingle, data);
      } 
      ...
    }
  }
```

https://github.com/ronin-chain/permit2x/blob/b3e2674f7c29b3ad9f00751eb162eac527ef4696/src/AllowanceTransfer.sol#L37-L44
```solidity
    function permit(address owner, PermitSingle memory permitSingle, bytes calldata signature) external {
        if (block.timestamp > permitSingle.sigDeadline) revert SignatureExpired(permitSingle.sigDeadline);

        // Verify the signer address from the signature.
        signature.verify(_hashTypedData(permitSingle.hash()), owner);

        _updateApproval(permitSingle.details, owner, permitSingle.spender);
    }

    /// @inheritdoc IAllowanceTransfer
    function permit(address owner, PermitBatch memory permitBatch, bytes calldata signature) external {
        if (block.timestamp > permitBatch.sigDeadline) revert SignatureExpired(permitBatch.sigDeadline);

        // Verify the signer address from the signature.
        signature.verify(_hashTypedData(permitBatch.hash()), owner);

        address spender = permitBatch.spender;
        unchecked {
            uint256 length = permitBatch.details.length;
            for (uint256 i = 0; i < length; ++i) {
                _updateApproval(permitBatch.details[i], owner, spender);
            }
        }
    }
```

### Recommended Mitigation
The signature and corresponding hash for the `PERMIT2.permit` functions can be updated to include `version` and `salt` and be also verified against these additional fields.

## [05] Using `SignatureVerification.verify` function that supports EIP-2098 increases attack surface

### Description
The `SignatureVerification.verify` function's `signature.length == 64` `else if` block supports EIP-2098. However, this increases the attack surface in which a malicious actor can resubmit an already-used signature that has 65 `signature.length` in a different form that has 64 `signature.length`, and such signature can still be verified.

https://github.com/ronin-chain/permit2x/blob/4543b4010f988dfb1cc46ee5ffa71eae5e8dece2/src/libraries/SignatureVerification.sol#L21-L46
```solidity
    function verify(bytes calldata signature, bytes32 hash, address claimedSigner) internal view {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (claimedSigner.code.length == 0) {
            if (signature.length == 65) {
                (r, s) = abi.decode(signature, (bytes32, bytes32));
                v = uint8(signature[64]);
@>          } else if (signature.length == 64) {
                // EIP-2098
                bytes32 vs;
                (r, vs) = abi.decode(signature, (bytes32, bytes32));
                s = vs & UPPER_BIT_MASK;
                v = uint8(uint256(vs >> 255)) + 27;
            } else {
                revert InvalidSignatureLength();
            }
            address signer = ecrecover(hash, v, r, s);
            if (signer == address(0)) revert InvalidSignature();
            if (signer != claimedSigner) revert InvalidSigner();
        } else {
            bytes4 magicValue = IERC1271(claimedSigner).isValidSignature(hash, signature);
            if (magicValue != IERC1271.isValidSignature.selector) revert InvalidContractSignature();
        }
    }
```

Therefore, if the nonce protection becomes ineffective, the signatures that have been used for calling the `PERMIT2.permit` functions through the `Dispatcher.dispatch` function can be replayed in a different form though such signatures should not be reused at all.

https://github.com/ronin-chain/katana-operation-contracts/blob/3dd0d8503aa4360e75a6acaddec3707c8581c188/src/aggregate-router/base/Dispatcher.sol#L28-L203
```solidity
  function dispatch(bytes1 commandType, bytes calldata inputs) internal returns (bool success, bytes memory output) {
    ...
    if (command < Commands.FIRST_IF_BOUNDARY) {
      ...
      } else if (command == Commands.PERMIT2_PERMIT_BATCH) {
        (IAllowanceTransfer.PermitBatch memory permitBatch,) =
          abi.decode(inputs, (IAllowanceTransfer.PermitBatch, bytes));
        bytes calldata data = inputs.toBytes(1);
        PERMIT2.permit(lockedBy, permitBatch, data);
      }
      ...
    } else {
      ...
      } else if (command == Commands.PERMIT2_PERMIT) {
        // equivalent: abi.decode(inputs, (IAllowanceTransfer.PermitSingle, bytes))
        IAllowanceTransfer.PermitSingle calldata permitSingle;
        assembly {
          permitSingle := inputs.offset
        }
        bytes calldata data = inputs.toBytes(6); // PermitSingle takes first 6 slots (0..5)
        PERMIT2.permit(lockedBy, permitSingle, data);
      } 
      ...
    }
  }
```

https://github.com/ronin-chain/permit2x/blob/b3e2674f7c29b3ad9f00751eb162eac527ef4696/src/AllowanceTransfer.sol#L37-L44
```solidity
    function permit(address owner, PermitSingle memory permitSingle, bytes calldata signature) external {
        if (block.timestamp > permitSingle.sigDeadline) revert SignatureExpired(permitSingle.sigDeadline);

        // Verify the signer address from the signature.
        signature.verify(_hashTypedData(permitSingle.hash()), owner);

        _updateApproval(permitSingle.details, owner, permitSingle.spender);
    }

    /// @inheritdoc IAllowanceTransfer
    function permit(address owner, PermitBatch memory permitBatch, bytes calldata signature) external {
        if (block.timestamp > permitBatch.sigDeadline) revert SignatureExpired(permitBatch.sigDeadline);

        // Verify the signer address from the signature.
        signature.verify(_hashTypedData(permitBatch.hash()), owner);

        address spender = permitBatch.spender;
        unchecked {
            uint256 length = permitBatch.details.length;
            for (uint256 i = 0; i < length; ++i) {
                _updateApproval(permitBatch.details[i], owner, spender);
            }
        }
    }
```
### Recommended Mitigation
The signature verification method can be updated to only support signatures that have 65 `signature.length`.

## [06] `UniswapV2Library.getAmountIn` function includes `amountOut > 0` requirement but `KatanaV2Library.getAmountIn` function does not

### Description
The `UniswapV2Library.getAmountIn` function executes `require(amountOut > 0, 'UniswapV2Library: INSUFFICIENT_OUTPUT_AMOUNT')` but the `KatanaV2Library.getAmountIn` function does not include such check.

https://github.com/Uniswap/v2-periphery/blob/master/contracts/libraries/UniswapV2Library.sol#L53-L59
```solidity
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) internal pure returns (uint amountIn) {
@>      require(amountOut > 0, 'UniswapV2Library: INSUFFICIENT_OUTPUT_AMOUNT');
        require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
        uint numerator = reserveIn.mul(amountOut).mul(1000);
        uint denominator = reserveOut.sub(amountOut).mul(997);
        amountIn = (numerator / denominator).add(1);
    }
```

https://github.com/ronin-chain/katana-operation-contracts/blob/b1dca6db461a35bbe2f43335d2895f8b2b4d80cf/src/aggregate-router/modules/katana/v2/KatanaV2Library.sol#L105-L114
```solidity
  function getAmountIn(uint256 amountOut, uint256 reserveIn, uint256 reserveOut)
    internal
    pure
    returns (uint256 amountIn)
  {
    if (reserveIn == 0 || reserveOut == 0) revert InvalidReserves();
    uint256 numerator = reserveIn * amountOut * 1000;
    uint256 denominator = (reserveOut - amountOut) * 997;
    amountIn = (numerator / denominator) + 1;
  }
```

If the `V2SwapRouter.v2SwapExactOutput` function is called with 0 as the `amountOut` input, such as due to a faulty interface that calls this function, after this function calls the `KatanaV2Library.getAmountInMultihop` function that further calls the `KatanaV2Library.getAmountIn` function, the `recipient` can unexpectedly receive 0 output tokens while some input tokens are sent.

https://github.com/ronin-chain/katana-operation-contracts/blob/d3b8711b064757393c4b3f5a63b91b5bd5549742/src/aggregate-router/modules/katana/v2/V2SwapRouter.sol#L83-L96
```solidity
  function v2SwapExactOutput(
    address recipient,
    uint256 amountOut,
    uint256 amountInMaximum,
    address[] calldata path,
    address payer
  ) internal {
    (uint256 amountIn, address firstPair) =
@>    KatanaV2Library.getAmountInMultihop(KATANA_V2_FACTORY, KATANA_V2_PAIR_INIT_CODE_HASH, amountOut, path);
    if (amountIn > amountInMaximum) revert V2TooMuchRequested();

    payOrPermit2Transfer(path[0], payer, firstPair, amountIn);
    _v2Swap(path, recipient, firstPair);
  }
```

https://github.com/ronin-chain/katana-operation-contracts/blob/b1dca6db461a35bbe2f43335d2895f8b2b4d80cf/src/aggregate-router/modules/katana/v2/KatanaV2Library.sol#L123-L137
```solidity
  function getAmountInMultihop(address factory, bytes32 initCodeHash, uint256 amountOut, address[] memory path)
    internal
    view
    returns (uint256 amount, address pair)
  {
    if (path.length < 2) revert InvalidPath();
    amount = amountOut;
    for (uint256 i = path.length - 1; i > 0; i--) {
      uint256 reserveIn;
      uint256 reserveOut;

      (pair, reserveIn, reserveOut) = pairAndReservesFor(factory, initCodeHash, path[i - 1], path[i]);
@>    amount = getAmountIn(amount, reserveIn, reserveOut);
    }
  }
```

### Recommended Mitigation
The `KatanaV2Library.getAmountIn` function can be updated to include the `amountOut > 0` requirement similar to what the `UniswapV2Library.getAmountIn` function does.

## [07] Solmate's `SafeTransferLib` used by `Payments` contract does not check if corresponding token has code or not

### Description
The `Payments` contract uses Solmate's `SafeTransferLib` to transfer ERC20 tokens in functions like `Payments.pay` and `Payments.payPortion`. If the corresponding ERC20 token does not exist yet or gets destroyed, these functions would not revert because Solmate's `SafeTransferLib` does not check if the corresponding token has code or not. In this case, calling these functions would not revert, and calling the `AggregateRouter.execute` function with the commands corresponding to these functions would not revert with the `ExecutionFailed` error since these commands' `success` returned by the `Dispatcher.dispatch` function would always be true. This would be confusing and cost more unnecessary gas to the users of these commands since no tokens are transferred at all.

https://github.com/ronin-chain/katana-operation-contracts/blob/d3b8711b064757393c4b3f5a63b91b5bd5549742/src/aggregate-router/modules/Payments.sol#L6
```solidity
import { SafeTransferLib } from "solmate/utils/SafeTransferLib.sol";
```

https://github.com/transmissions11/solmate/blob/f2833c7cc951c50e0b5fd7e505571fddc10c8f77/src/utils/SafeTransferLib.sol#L9
```solidity
/// @dev Note that none of the functions in this library check that a token has code at all! That responsibility is delegated to the caller.
```

https://github.com/ronin-chain/katana-operation-contracts/blob/d3b8711b064757393c4b3f5a63b91b5bd5549742/src/aggregate-router/modules/Payments.sol#L26-L36
```solidity
  function pay(address token, address recipient, uint256 value) internal {
    if (token == Constants.ETH) {
      recipient.safeTransferETH(value);
    } else {
      if (value == Constants.CONTRACT_BALANCE) {
        value = ERC20(token).balanceOf(address(this));
      }

@>    ERC20(token).safeTransfer(recipient, value);
    }
  }
```

https://github.com/ronin-chain/katana-operation-contracts/blob/d3b8711b064757393c4b3f5a63b91b5bd5549742/src/aggregate-router/modules/Payments.sol#L42-L53
```solidity
  function payPortion(address token, address recipient, uint256 bips) internal {
    if (bips == 0 || bips > FEE_BIPS_BASE) revert InvalidBips();
    if (token == Constants.ETH) {
      uint256 balance = address(this).balance;
      uint256 amount = (balance * bips) / FEE_BIPS_BASE;
      recipient.safeTransferETH(amount);
    } else {
      uint256 balance = ERC20(token).balanceOf(address(this));
      uint256 amount = (balance * bips) / FEE_BIPS_BASE;
@>    ERC20(token).safeTransfer(recipient, amount);
    }
  }
```

https://github.com/ronin-chain/katana-operation-contracts/blob/f568dd561409beb4fdc8e80906b66377b31f7a8a/src/aggregate-router/AggregateRouter.sol#L37-L59
```solidity
  function execute(bytes calldata commands, bytes[] calldata inputs) public payable override isNotLocked {
    bool success;
    bytes memory output;
    uint256 numCommands = commands.length;
    if (inputs.length != numCommands) revert LengthMismatch();

    // loop through all given commands, execute them and pass along outputs as defined
    for (uint256 commandIndex = 0; commandIndex < numCommands;) {
      bytes1 command = commands[commandIndex];

      bytes calldata input = inputs[commandIndex];

      (success, output) = dispatch(command, input);

      if (!success && successRequired(command)) {
        revert ExecutionFailed({ commandIndex: commandIndex, message: output });
      }

      unchecked {
        commandIndex++;
      }
    }
  }
```

### Recommended Mitigation
The `Payments` contract can be updated to use Openzeppelin's `SafeERC20` library for transferring ERC20 tokens.

## [08] `Dispatcher.dispatch` function call to further call `permit2TransferFrom` functions can revert

### Description
When the `Dispatcher.dispatch` function is called to further call the `PERMIT2.permit` functions, the `AllowanceTransfer._updateApproval` function is eventually called to update the `owner`'s token `allowance` for the `AggregateRouter` to spend, where such `allowance` is tracked in the `AllowanceTransfer` contract.

https://github.com/ronin-chain/katana-operation-contracts/blob/3dd0d8503aa4360e75a6acaddec3707c8581c188/src/aggregate-router/base/Dispatcher.sol#L28-L203
```solidity
  function dispatch(bytes1 commandType, bytes calldata inputs) internal returns (bool success, bytes memory output) {
    uint256 command = uint8(commandType & Commands.COMMAND_TYPE_MASK);

    success = true;
    ...
      } else if (command == Commands.PERMIT2_TRANSFER_FROM) {
        // equivalent: abi.decode(inputs, (address, address, uint160))
        address token;
        address recipient;
        uint160 amount;
        assembly {
          token := calldataload(inputs.offset)
          recipient := calldataload(add(inputs.offset, 0x20))
          amount := calldataload(add(inputs.offset, 0x40))
        }
        permit2TransferFrom(token, lockedBy, map(recipient), amount);
      } else if (command == Commands.PERMIT2_PERMIT_BATCH) {
        (IAllowanceTransfer.PermitBatch memory permitBatch,) =
          abi.decode(inputs, (IAllowanceTransfer.PermitBatch, bytes));
        bytes calldata data = inputs.toBytes(1);
        PERMIT2.permit(lockedBy, permitBatch, data);
      }
      ...
    } else {
      ...
      } else if (command == Commands.PERMIT2_PERMIT) {
        // equivalent: abi.decode(inputs, (IAllowanceTransfer.PermitSingle, bytes))
        IAllowanceTransfer.PermitSingle calldata permitSingle;
        assembly {
          permitSingle := inputs.offset
        }
        bytes calldata data = inputs.toBytes(6); // PermitSingle takes first 6 slots (0..5)
        PERMIT2.permit(lockedBy, permitSingle, data);
      }
      ...
      } else if (command == Commands.PERMIT2_TRANSFER_FROM_BATCH) {
        (IAllowanceTransfer.AllowanceTransferDetails[] memory batchDetails) =
          abi.decode(inputs, (IAllowanceTransfer.AllowanceTransferDetails[]));
        permit2TransferFrom(batchDetails, lockedBy);
      }
      ...
    }
  }
```

https://github.com/ronin-chain/permit2x/blob/b3e2674f7c29b3ad9f00751eb162eac527ef4696/src/AllowanceTransfer.sol#L135-L149
```solidity
    function _updateApproval(PermitDetails memory details, address owner, address spender)
        private
        onlyGrantedSpender(spender)
    {
        uint48 nonce = details.nonce;
        address token = details.token;
        uint160 amount = details.amount;
        uint48 expiration = details.expiration;
        PackedAllowance storage allowed = allowance[owner][token][spender];

        if (allowed.nonce != nonce) revert InvalidNonce();

        allowed.updateAll(amount, expiration, nonce);
        emit Permit(owner, token, spender, amount, expiration, nonce);
    }
```

Later, when the `Dispatcher.dispatch` function is called to further call the `permit2TransferFrom` functions, the `AggregateRouter` contract eventually calls the `PERMIT2` contract that inherits the `AllowanceTransfer` contract. When the `AllowanceTransfer._transfer` function is called, the `owner`'s allowance for the `AggregateRouter` contract tracked in the `AllowanceTransfer` contract can be correctly deducted but such function call can still revert when executing `ERC20(token).safeTransferFrom(from, to, amount)`. Although such execution needs the `PERMIT2` contract to be the `owner`'s spender in the `token` contract, the `owner` usually would expect to approve the `AggregateRouter` contract, instead of the `PERMIT2` contract, to spend his token in the `token` contract. Therefore, such `ERC20(token).safeTransferFrom(from, to, amount)` execution would revert and waste the `Dispatcher.dispatch` function caller's gas.

https://github.com/ronin-chain/katana-operation-contracts/blob/bb2ee8761b43ee472917af36369df056aae19265/src/aggregate-router/modules/Permit2Payments.sol#L20-L34
```solidity
  function permit2TransferFrom(address token, address from, address to, uint160 amount) internal {
    PERMIT2.transferFrom(from, to, amount, token);
  }
  
  ...
  function permit2TransferFrom(IAllowanceTransfer.AllowanceTransferDetails[] memory batchDetails, address owner)
    internal
  {
    uint256 batchLength = batchDetails.length;
    for (uint256 i = 0; i < batchLength; ++i) {
      if (batchDetails[i].from != owner) revert FromAddressIsNotOwner();
    }
    PERMIT2.transferFrom(batchDetails);
  }
```

https://github.com/ronin-chain/permit2x/blob/b3e2674f7c29b3ad9f00751eb162eac527ef4696/src/AllowanceTransfer.sol#L80-L98
```solidity
    function _transfer(address from, address to, uint160 amount, address token) private {
        PackedAllowance storage allowed = allowance[from][token][msg.sender];

        if (block.timestamp > allowed.expiration) revert AllowanceExpired(allowed.expiration);

        uint256 maxAmount = allowed.amount;
        if (maxAmount != type(uint160).max) {
            if (amount > maxAmount) {
                revert InsufficientAllowance(maxAmount);
            } else {
                unchecked {
                    allowed.amount = uint160(maxAmount) - amount;
                }
            }
        }

        // Transfer the tokens from the from address to the recipient.
@>      ERC20(token).safeTransferFrom(from, to, amount);
    }
```

### Recommended Mitigation
The transfer mechanism when the `Dispatcher.dispatch` function is called to further call the `permit2TransferFrom` functions can be updated to let the `AggregateRouter` contract to additionally call the `token` contract for transferring the `owner`'s tokens.

## [09] Calling `Payments.pay` function with `Constants.CONTRACT_BALANCE` as `value` input when `token` is ETH can revert and waste gas

### Description
Calling the `Payments.pay` function with `Constants.CONTRACT_BALANCE` as the `value` input can transfer all of the `Payments` contract's `token` balance if the `token` is an ERC20 token. Because of this, the `Payments.pay` function caller would expect that calling this function with `Constants.CONTRACT_BALANCE` as the `value` input when the `token` is ETH can send all of the `Payments` contract's ETH balance to the recipient but this is not the case. In this case, such function call would attempt to send `Constants.CONTRACT_BALANCE` ETH to the recipient, which would revert due to the insufficient ETH balance and waste the caller's gas.

https://github.com/ronin-chain/katana-operation-contracts/blob/d3b8711b064757393c4b3f5a63b91b5bd5549742/src/aggregate-router/modules/Payments.sol#L26-L36
```solidity
  function pay(address token, address recipient, uint256 value) internal {
    if (token == Constants.ETH) {
      recipient.safeTransferETH(value);
    } else {
      if (value == Constants.CONTRACT_BALANCE) {
        value = ERC20(token).balanceOf(address(this));
      }

      ERC20(token).safeTransfer(recipient, value);
    }
  }
```

### Recommended Mitigation
The `Payments.pay` function can be updated to send all of the `Payments` contract's ETH balance to the recipient when the `token` input is ETH and the `value` input is `Constants.CONTRACT_BALANCE`.

## [10] `KatanaV3Factory.initialize` function can be frontrun

### Description
(Please note: this finding's instance is not found in https://github.com/code-423n4/2024-10-ronin/blob/main/4naly3er-report.md#l-8-initializers-could-be-front-run.)

The `KatanaV3Factory.initialize` function can be frontrun by a malicious actor to set `beacon`, `owner`, and `treasury` to values that are unintended to the protocol. After such frontrunning, the protocol would be forced to redeploy the `KatanaV3Factory` contract.

https://github.com/ronin-chain/katana-v3-contracts/blob/3ffd56300ced6ec42c5dcbe28d4420c5011e49e2/src/core/KatanaV3Factory.sol#L46-L74
```solidity
  function initialize(address beacon_, address owner_, address treasury_) external {
    require(beacon == address(0), "KatanaV3Factory: ALREADY_INITIALIZED");

    require(beacon_ != address(0), "KatanaV3Factory: INVALID_BEACON");
    require(owner_ != address(0), "KatanaV3Factory: INVALID_OWNER");
    require(treasury_ != address(0), "KatanaV3Factory: INVALID_TREASURY");

    // this beacon is treated as immutable
    // so there is no need to emit an event
    beacon = beacon_;

    // owner is also treated as immutable
    owner = owner_;

    treasury = treasury_;
    ...
  }
```

### Recommended Mitigation
One way to mitigate this is to update the `KatanaV3Factory.initialize` function to be only callable by the address that is trusted by the protocol.

## [11] Missing `address(0)` checks in `V3Migrator` and `PeripheryImmutableState` contracts' constructors

### Description
(Please note: this finding's instances are not found in https://github.com/code-423n4/2024-10-ronin/blob/main/4naly3er-report.md#l-3-missing-checks-for-address0-when-assigning-values-to-address-state-variables.)

In `V3Migrator` and `PeripheryImmutableState` contracts' constructors, the `_nonfungiblePositionManager`, `_factory`, and `_WETH9` inputs are not checked against `address(0)`. Thus, their corresponding state variables can be set to `address(0)` unexpectedly.

https://github.com/ronin-chain/katana-v3-contracts/blob/b841b153c44e9f30a4971610c2543c4c0a8321ce/src/periphery/V3Migrator.sol#L26-L30
```solidity
  constructor(address _factory, address _WETH9, address _nonfungiblePositionManager)
    PeripheryImmutableState(_factory, _WETH9)
  {
    nonfungiblePositionManager = _nonfungiblePositionManager;
  }
```

https://github.com/ronin-chain/katana-v3-contracts/blob/a9196effc33500def61ea9bb969238dc649b9de9/src/periphery/base/PeripheryImmutableState.sol#L17-L21
```solidity
  constructor(address _factory, address _WETH9) {
    factory = _factory;
    WETH9 = _WETH9;
    governance = IKatanaV3Factory(_factory).owner();
  }
```

### Recommended Mitigation
The `V3Migrator` and `PeripheryImmutableState` contracts' constructors can be updated to revert if one of the `_nonfungiblePositionManager`, `_factory`, and `_WETH9` inputs equals `address(0)`.

## [12] Unlocked Solidity version in contracts

### Description
(Please note: this finding's instances are not found in https://github.com/code-423n4/2024-10-ronin/blob/main/4naly3er-report.md#l-15-unspecific-compiler-version-pragma.)

Solidity versions are not locked in contracts like `AggregateRouter`, `Dispatcher`, `V3SwapRouter`, `V2SwapRouter`, and `Payments`. Hence, it is possible that the compiler version used for testing and deploying these contracts is later changed when a redeployment is needed. In this case, the different compiler can introduce bugs and compatibility issues with these contracts that were not found before.

https://github.com/ronin-chain/katana-operation-contracts/blob/f568dd561409beb4fdc8e80906b66377b31f7a8a/src/aggregate-router/AggregateRouter.sol#L2
```solidity
pragma solidity ^0.8.17;
```

https://github.com/ronin-chain/katana-operation-contracts/blob/3dd0d8503aa4360e75a6acaddec3707c8581c188/src/aggregate-router/base/Dispatcher.sol#L2
```solidity
pragma solidity ^0.8.17;
```

https://github.com/ronin-chain/katana-operation-contracts/blob/3dd0d8503aa4360e75a6acaddec3707c8581c188/src/aggregate-router/modules/katana/v3/V3SwapRouter.sol#L2
```solidity
pragma solidity ^0.8.17;
```

https://github.com/ronin-chain/katana-operation-contracts/blob/d3b8711b064757393c4b3f5a63b91b5bd5549742/src/aggregate-router/modules/katana/v2/V2SwapRouter.sol#L2
```solidity
pragma solidity ^0.8.17;
```

https://github.com/ronin-chain/katana-operation-contracts/blob/d3b8711b064757393c4b3f5a63b91b5bd5549742/src/aggregate-router/modules/Payments.sol#L2
```solidity
pragma solidity ^0.8.17;
```

### Recommended Mitigation
Solidity version in contracts like `AggregateRouter`, `Dispatcher`, `V3SwapRouter`, `V2SwapRouter`, and `Payments` can be updated to be locked.