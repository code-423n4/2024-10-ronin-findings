QA1. KatanaV3Pool.swap() can be improved by early loop continue for the case when ```state.liquidity = 0``` for the while loop. 

The observation is that no swap will occur for the step when ```state.liquidity = 0```.

Firt of all, ```tickBitmap.nextInitializedTickWithinOneWord(state.tick, cache.tickSpacing, zeroForOne)``` will only search 256 ticks, and in many cases, as shown by the following test, we have ```step.initialized = 0```, that is, we end up in the next tick that has no liquidity.

```javasript
  function testSwap1() public{
      KatanaV3Pool pool = pools[0];
      printBalances(treasury, "Balances for treasury before swap"); 
      printBalances(address(this), "Balances for this before swap");
      int256 minPrice = TickMath.MIN_SQRT_RATIO + 1;
      console2.logInt(minPrice);
      (int256 amount0, int256 amount1) = pool.swap(address(this), true, 10_000_000, TickMath.MIN_SQRT_RATIO + 1, "");  // the price is square root price * x96?
      console2.logInt(amount0);
      console2.logInt(amount1);

      printBalances(address(this), "Balances for this after swap");
       printBalances(treasury, "Balances for treasury after swap"); 
  }
}
```

When such tick is reached, there is no real swap that will occur,  In such cases, it's efficient to skip over to the next iteration by only adjusting that ```state.tick = zeroForOne ? step.tickNext - 1 : step.tickNext;``` so we can continue to search for initialized tick. Much computation can be skipped since ```step.amountIn = 0```, ```step.amountOut = 0```, and ```step.feeAmount = 0``` in this case. 


Here is the improved code: 

```diff
function swap(
    address recipient,
    bool zeroForOne,
    int256 amountSpecified,
    uint160 sqrtPriceLimitX96,
    bytes calldata data
  ) external override returns (int256 amount0, int256 amount1) {
     

    // when quoting, we don't need to check authorization
    if (tx.origin != address(0)) {
      require(msg.sender == IKatanaGovernance(governance).getRouter(), "IR"); 
    }

    require(amountSpecified != 0, "AS");

    Slot0 memory slot0Start = slot0;

    require(slot0Start.unlocked, "LOK");
    require(
      zeroForOne
        ? sqrtPriceLimitX96 < slot0Start.sqrtPriceX96 && sqrtPriceLimitX96 > TickMath.MIN_SQRT_RATIO
        : sqrtPriceLimitX96 > slot0Start.sqrtPriceX96 && sqrtPriceLimitX96 < TickMath.MAX_SQRT_RATIO,
      "SPL"
    );

    slot0.unlocked = false;

    SwapCache memory cache = SwapCache({
      liquidityStart: liquidity,
      blockTimestamp: _blockTimestamp(),
      fee: fee,
      feeProtocolNum: slot0Start.feeProtocolNum,
      feeProtocolDen: slot0Start.feeProtocolDen,
      tickSpacing: tickSpacing,
      secondsPerLiquidityCumulativeX128: 0,
      tickCumulative: 0,
      computedLatestObservation: false
    });

    bool exactInput = amountSpecified > 0;

    SwapState memory state = SwapState({
      amountSpecifiedRemaining: amountSpecified,
      amountCalculated: 0,
      sqrtPriceX96: slot0Start.sqrtPriceX96,
      tick: slot0Start.tick,
      feeGrowthGlobalX128: zeroForOne ? feeGrowthGlobal0X128 : feeGrowthGlobal1X128,
      protocolFee: 0,
      liquidity: cache.liquidityStart
    });

    // continue swapping as long as we haven't used the entire input/output and haven't reached the price limit
    while (state.amountSpecifiedRemaining != 0 && state.sqrtPriceX96 != sqrtPriceLimitX96) { // reach the limit... why not allowing reaching the limit
      StepComputations memory step;

      

      step.sqrtPriceStartX96 = state.sqrtPriceX96; // the price we will use

      
      // since the following only search 256 ticks, it is possible none of them are initialized, in this case, 
      // step.tickNext = state.tick - 255 (token0 for token1 trade), and step.intialized = false, and we need to search another 256 ticks
      (step.tickNext, step.initialized) =
      tickBitmap.nextInitializedTickWithinOneWord(state.tick, cache.tickSpacing, zeroForOne);  // if zerForOne, then tickNext should decrease by 1 sicne token0 price will drop

      if(step.initialized){
            console2.log("state.amountSpecifiedRemaing: ", state.amountSpecifiedRemaining);
            console2.log("state.sqrtPriceX96:", uint256(state.sqrtPriceX96));
            console2.log("state.tick: ", uint256(state.tick));
            console2.log("step:tickNext: ", uint256(step.tickNext));
            console2.log("step.initialized: ", step.initialized);
      }

      // ensure that we do not overshoot the min/max tick, as the tick bitmap is not aware of these bounds
      if (step.tickNext < TickMath.MIN_TICK) {
        step.tickNext = TickMath.MIN_TICK;
      } else if (step.tickNext > TickMath.MAX_TICK) {
        step.tickNext = TickMath.MAX_TICK;
      }

      // get the price for the next tick
      step.sqrtPriceNextX96 = TickMath.getSqrtRatioAtTick(step.tickNext); // each tick correponds to a price

      
      // compute values to swap to the target tick, price limit, or point where input/output amount is exhausted
      // when state.liquidity = 0; then state.aqrtPriceX96 will be calcuated to refedt price movement, but the remaining onese will be zero
      // since no swap actually occurs
      (state.sqrtPriceX96, step.amountIn, step.amountOut, step.feeAmount) = SwapMath.computeSwapStep(
        state.sqrtPriceX96,
        (zeroForOne ? step.sqrtPriceNextX96 < sqrtPriceLimitX96 : step.sqrtPriceNextX96 > sqrtPriceLimitX96)
          ? sqrtPriceLimitX96
          : step.sqrtPriceNextX96,
        state.liquidity,
        state.amountSpecifiedRemaining,
        cache.fee
      );

+     if(state.liquidity == 0){
+         state.tick = zeroForOne ? step.tickNext - 1 : step.tickNext;    
+         continue;      
+     }
    

      if (exactInput) {  // what specified is for input
        state.amountSpecifiedRemaining -= (step.amountIn + step.feeAmount).toInt256(); // This variable tracks how much of the input amount is left to swap.
        // This tracks how much of the output token has been received so far, it is a negqtive number, so sub
        state.amountCalculated = state.amountCalculated.sub(step.amountOut.toInt256()); 
             }
      else {   // what specified is for output
        state.amountSpecifiedRemaining += step.amountOut.toInt256();    // specify how much remaining output need to be filled, a negative number
        state.amountCalculated = state.amountCalculated.add((step.amountIn + step.feeAmount).toInt256());  // specify how much input tokens have been used
      }

      // if the protocol fee is on, calculate how much is owed, decrement feeAmount, and increment protocolFee
      if (cache.feeProtocolNum > 0) {
        uint256 delta = FullMath.mulDiv(step.feeAmount, cache.feeProtocolNum, cache.feeProtocolDen);
        step.feeAmount -= delta;
        state.protocolFee += uint128(delta);
      }

      // update global fee tracker
      if (state.liquidity > 0) {
        state.feeGrowthGlobalX128 += FullMath.mulDiv(step.feeAmount, FixedPoint128.Q128, state.liquidity);
      }

      // shift tick if we reached the next price
      if (state.sqrtPriceX96 == step.sqrtPriceNextX96) {
        // if the tick is initialized, run the tick transition
        if (step.initialized) {
          // check for the placeholder value, which we replace with the actual value the first time the swap
          // crosses an initialized tick
          if (!cache.computedLatestObservation) {
            (cache.tickCumulative, cache.secondsPerLiquidityCumulativeX128) = observations.observeSingle(
              cache.blockTimestamp,
              0,
              slot0Start.tick,
              slot0Start.observationIndex,
              cache.liquidityStart,
              slot0Start.observationCardinality
            );
            cache.computedLatestObservation = true;
          }
          int128 liquidityNet = ticks.cross(
            step.tickNext,
            (zeroForOne ? state.feeGrowthGlobalX128 : feeGrowthGlobal0X128),
            (zeroForOne ? feeGrowthGlobal1X128 : state.feeGrowthGlobalX128),
            cache.secondsPerLiquidityCumulativeX128,
            cache.tickCumulative,
            cache.blockTimestamp
          );
          // if we're moving leftward, we interpret liquidityNet as the opposite sign
          // safe because liquidityNet cannot be type(int128).min
          if (zeroForOne) liquidityNet = -liquidityNet;

          state.liquidity = LiquidityMath.addDelta(state.liquidity, liquidityNet);
        }

        state.tick = zeroForOne ? step.tickNext - 1 : step.tickNext;
      } else if (state.sqrtPriceX96 != step.sqrtPriceStartX96) {
        // recompute unless we're on a lower tick boundary (i.e. already transitioned ticks), and haven't moved
        state.tick = TickMath.getTickAtSqrtRatio(state.sqrtPriceX96);
      }
    } // end while?

    // update tick and write an oracle entry if the tick change
    if (state.tick != slot0Start.tick) {
      (uint16 observationIndex, uint16 observationCardinality) = observations.write(
        slot0Start.observationIndex,
        cache.blockTimestamp,
        slot0Start.tick,
        cache.liquidityStart,
        slot0Start.observationCardinality,
        slot0Start.observationCardinalityNext
      );
      (slot0.sqrtPriceX96, slot0.tick, slot0.observationIndex, slot0.observationCardinality) =
        (state.sqrtPriceX96, state.tick, observationIndex, observationCardinality);
    } else {
      // otherwise just update the price
      slot0.sqrtPriceX96 = state.sqrtPriceX96;
    }

    // update liquidity if it changed
    if (cache.liquidityStart != state.liquidity) liquidity = state.liquidity;

    address tokenIn = zeroForOne ? token0 : token1;
    address tokenOut = zeroForOne ? token1 : token0;

    // update fee growth global
    if (zeroForOne) feeGrowthGlobal0X128 = state.feeGrowthGlobalX128;
    else feeGrowthGlobal1X128 = state.feeGrowthGlobalX128;

    (amount0, amount1) = zeroForOne == exactInput       
      ? (amountSpecified - state.amountSpecifiedRemaining, state.amountCalculated)
      : (state.amountCalculated, amountSpecified - state.amountSpecifiedRemaining);

    // do the transfers and collect payment
    if (zeroForOne) {
      if (amount1 < 0) TransferHelper.safeTransfer(tokenOut, recipient, uint256(-amount1)); // send token1 to recipient

      uint256 balance0Before = balance0();
      IKatanaV3SwapCallback(msg.sender).katanaV3SwapCallback(amount0, amount1, data); // please send me your token0 of amount0
      require(balance0Before.add(uint256(amount0)) <= balance0(), "IIA"); // sufficient
    } else {
      if (amount0 < 0) TransferHelper.safeTransfer(tokenOut, recipient, uint256(-amount0));  // send token0 to recipient

      uint256 balance1Before = balance1();
      IKatanaV3SwapCallback(msg.sender).katanaV3SwapCallback(amount0, amount1, data);
      require(balance1Before.add(uint256(amount1)) <= balance1(), "IIA");  // receive sufficient token1
    }

    // transfer protocol fees to the treasury
    if (state.protocolFee > 0) {
      TransferHelper.safeTransfer(tokenIn, IKatanaV3Factory(factory).treasury(), state.protocolFee);
    }

    emit Swap(msg.sender, recipient, amount0, amount1, state.sqrtPriceX96, state.liquidity, state.tick);
    slot0.unlocked = true;
  }
```

QA2. NonfungiblePositionManager.collect() fails to collect all tokens in (position.tokensOwed0, position.tokensOwed1) as expected. However, the function comment says "Must collect all tokens owed".

This is because it executes the following line first and then performs an update of the position fees owed and fee growth snapshot, which gave a new (position.tokensOwed0, position.tokensOwed1).

```javascipt
 (uint128 tokensOwed0, uint128 tokensOwed1) = (position.tokensOwed0, position.tokensOwed1);
```

Therefore, what is collected is only partial, not the whole amount of token0 and token1. 

Mitigation: first calculate the new (position.tokensOwed0, position.tokensOwed1), then uses it to decide the amount of token0 and token1 that need to be collected. 


QA3. The NonfungilePositionManager.collect() calls KatanaV3Pool.mint with zero dealLiquidity to trigger the pool to update the position's fee calculations for the position’s current tick range. To save gas, this can be achieved by adding a new function accrue() instead to use a general mint function to achieve the same. 
