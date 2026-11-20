import assert from "node:assert/strict";

import {
  SOL_MINT,
  Wallet,
  buildDepositTransaction,
  buildTransferTransaction,
  syncWallet,
} from "@heliuslabs/spr";
import { buildRegistrationTransaction, isWalletRegistered } from "@heliuslabs/spr/wallet";

import { expectBalance, localWalletKeys, sendAndConfirmFactory, setup } from "./setup.js";

const AMOUNT = 3_000_000n;

async function main(): Promise<void> {
  const { zolana, service, sender, recipient } = await setup();
  if (await isWalletRegistered({ rpc: zolana, owner: recipient.address })) {
    throw new Error("the example requires a recipient without a registry record");
  }
  const distinctOwners = sender.address !== recipient.address;
  const publicBalance = await zolana.getBalance(recipient.address);
  if (distinctOwners) assert.equal(publicBalance, 0n);
  let serviceKeys: Awaited<ReturnType<typeof service.open>> | undefined;
  let keys: Awaited<ReturnType<typeof localWalletKeys>> | undefined;
  let ownKeys: typeof keys;
  try {
    keys = await localWalletKeys(sender, zolana.proofService);
    const send = sendAndConfirmFactory(zolana, sender);
    if (distinctOwners) {
      const registration = await buildRegistrationTransaction({
        client: zolana,
        owner: sender.address,
        address: keys.address(),
      });
      if (registration) await send(registration);
      assert.equal(await isWalletRegistered({ rpc: zolana, owner: sender.address }), true);
    }

    const wallet = new Wallet({ identity: keys.address() });
    const deposit = await buildDepositTransaction({
      client: zolana,
      feePayer: sender.address,
      recipient: keys.address(),
      amount: AMOUNT,
    });
    const depositTx = await send(deposit);
    await syncWallet({ client: zolana, wallet, keys, config: { requireSlot: depositTx.slot } });

    const transfer = await buildTransferTransaction({
      client: zolana,
      wallet,
      keys,
      feePayer: sender.address,
      recipient: recipient.address,
      decryptionService: service,
      amount: AMOUNT,
    });
    const transferTx = await send(transfer);

    assert.equal(await isWalletRegistered({ rpc: zolana, owner: recipient.address }), false);
    if (distinctOwners) {
      assert.equal(await zolana.getBalance(recipient.address), publicBalance);
      ownKeys = await localWalletKeys(recipient, zolana.proofService);
      const registration = await buildRegistrationTransaction({
        client: zolana,
        owner: recipient.address,
        address: ownKeys.address(),
        payer: sender.address,
      });
      assert.ok(registration);
      await sendAndConfirmFactory(zolana, sender, recipient)(registration);
      assert.equal(await isWalletRegistered({ rpc: zolana, owner: recipient.address }), true);
    }

    serviceKeys = await service.open(recipient, zolana.proofService);
    const received = new Wallet({ identity: serviceKeys.address() });
    await syncWallet({
      client: zolana,
      wallet: received,
      keys: serviceKeys,
      config: { requireSlot: transferTx.slot },
    });
    expectBalance("receive", received.balance(SOL_MINT), AMOUNT, 1);

    ownKeys ??= keys;
    const sweep = await buildTransferTransaction({
      client: zolana,
      wallet: received,
      keys: serviceKeys,
      feePayer: sender.address,
      recipient: distinctOwners ? recipient.address : ownKeys.address(),
      decryptionService: service,
      amount: AMOUNT,
    });
    const sweepSend = sender.address === recipient.address ? send : sendAndConfirmFactory(zolana, sender, recipient);
    const sweepTx = await sweepSend(sweep);
    const own = new Wallet({ identity: ownKeys.address() });
    await syncWallet({
      client: zolana,
      wallet: own,
      keys: ownKeys,
      config: { requireSlot: sweepTx.slot },
    });
    expectBalance("sweep", own.balance(SOL_MINT), AMOUNT, 1);
    if (distinctOwners) assert.equal(await zolana.getBalance(recipient.address), publicBalance);
    console.log(`sweep recipient=${recipient.address} private_balance=${AMOUNT} tx=${sweepTx.signature}`);
  } finally {
    serviceKeys?.destroy();
    if (ownKeys !== keys) ownKeys?.destroy();
    keys?.destroy();
  }
}

await main();
