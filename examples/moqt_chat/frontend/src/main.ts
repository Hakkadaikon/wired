// Entry point: wires domRenderer.ts and moqtClient.ts to the DOM.
// Ported from examples/webtransport_chat/public/app.js.

import { MoqtChatClient } from "./lib/moqtClient";
import { DomRenderer } from "./lib/domRenderer";

function requireEl<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
}

function main(): void {
  const renderer = new DomRenderer({
    messageListEl: requireEl("messages"),
    statusEl: requireEl("status"),
    formEl: requireEl<HTMLFormElement>("chat-form"),
    textInputEl: requireEl<HTMLInputElement>("text"),
    authorInputEl: requireEl<HTMLInputElement>("author"),
    certHashInputEl: requireEl<HTMLInputElement>("certHash"),
    urlInputEl: requireEl<HTMLInputElement>("url"),
    connectButtonEl: requireEl<HTMLButtonElement>("connect"),
  });

  let client: MoqtChatClient | null = null;

  renderer.onConnectClick(async () => {
    const localId = renderer.getAuthorInput();
    if (!localId) {
      window.alert("participant id is required");
      return;
    }
    const url = renderer.getUrlInput();
    const certHashes = renderer.getCertHashInput();

    client = new MoqtChatClient(localId, {
      onStatusChange: (status) => renderer.setConnectionStatus(status),
      onMessage: (participantId, text) => renderer.appendMessage(participantId, text),
    });

    try {
      await client.connect(url, certHashes);
    } catch (err) {
      renderer.setConnectionStatus("disconnected");
      console.error("connect failed", err);
    }
  });

  renderer.onFormSubmit((text) => {
    if (!client) return;
    const author = renderer.getAuthorInput();
    renderer.appendMessage(author, text);
    client.send(text).catch((err) => console.error("send failed", err));
  });
}

document.addEventListener("DOMContentLoaded", main);
