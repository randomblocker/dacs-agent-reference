import { test } from "node:test";
import assert from "node:assert/strict";
import { MessagingPeer, type MessagingPeerInstance } from "./demosdk.js";

interface TestPeer extends MessagingPeerInstance {
  awaitResponse(
    type: string,
    filter?: (message: { type?: unknown; payload?: unknown }) => boolean,
    timeout?: number,
  ): Promise<unknown>;
  sendToServer(message: unknown): void;
  sendToServerAndWait(
    message: unknown,
    type: string,
    options?: {
      timeout?: number;
      filterFn?: (message: { type?: unknown; payload?: unknown }) => boolean;
    },
  ): Promise<unknown>;
  handleMessage(message: unknown): void;
}

function testPeer(): TestPeer {
  return new MessagingPeer({
    serverUrl: "ws://unused.invalid",
    clientId: "reliable-transport-test",
    publicKey: new Uint8Array(),
  }) as TestPeer;
}

test("messaging request installs its response waiter before sending", async () => {
  const peer = testPeer();
  peer.sendToServer = () => {
    // Model a zero-latency server response. demosdk 4.0.16 loses this because
    // its stock implementation sends first and registers the waiter second.
    peer.handleMessage({
      type: "public_key_response",
      payload: { peerId: "seller", publicKey: [1, 2, 3] },
    });
  };

  const response = await peer.sendToServerAndWait(
    { type: "request_public_key", payload: { targetId: "seller" } },
    "public_key_response",
    {
      timeout: 100,
      filterFn: (message) => (message.payload as { peerId?: unknown } | undefined)?.peerId === "seller",
    },
  );
  assert.deepEqual(response, { peerId: "seller", publicKey: [1, 2, 3] });
});

test("messaging waiter survives unrelated and concurrently correlated frames", async () => {
  const peer = testPeer();
  const seller = peer.awaitResponse(
    "public_key_response",
    (message) => (message.payload as { peerId?: unknown } | undefined)?.peerId === "seller",
    100,
  );
  const buyer = peer.awaitResponse(
    "public_key_response",
    (message) => (message.payload as { peerId?: unknown } | undefined)?.peerId === "buyer",
    100,
  );

  peer.handleMessage({ type: "discover", payload: { peers: ["seller", "buyer"] } });
  peer.handleMessage({ type: "public_key_response", payload: { peerId: "buyer", publicKey: [4] } });
  peer.handleMessage({ type: "public_key_response", payload: { peerId: "seller", publicKey: [5] } });

  assert.deepEqual(await buyer, { peerId: "buyer", publicKey: [4] });
  assert.deepEqual(await seller, { peerId: "seller", publicKey: [5] });
});
