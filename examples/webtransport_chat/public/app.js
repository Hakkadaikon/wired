import { ChatSession } from './application/chatSession.js';
import { WebTransportClient } from './infrastructure/webtransportClient.js';
import { DomRenderer } from './infrastructure/domRenderer.js';

function main() {
  const renderer = new DomRenderer({
    messageListEl: document.getElementById('messages'),
    statusEl: document.getElementById('status'),
    formEl: document.getElementById('chat-form'),
    textInputEl: document.getElementById('text'),
    authorInputEl: document.getElementById('author'),
    certHashInputEl: document.getElementById('certHash'),
  });

  let session = null;

  document.getElementById('connect').addEventListener('click', async () => {
    const url = document.getElementById('url').value.trim();
    const certHashesHex = renderer
      .getCertHashInput()
      .split(',')
      .map((h) => h.trim())
      .filter((h) => h.length > 0);

    renderer.setConnectionStatus('connecting');
    const client = new WebTransportClient(url, certHashesHex);
    session = new ChatSession(client);
    session.onMessageReceived((message) => renderer.appendMessage(message));

    try {
      await session.connect();
      renderer.setConnectionStatus('connected');
    } catch (err) {
      renderer.setConnectionStatus('disconnected');
      console.error('connect failed', err);
    }
  });

  renderer.onFormSubmit((author, text) => {
    if (!session) return;
    session.send(author, text);
  });
}

document.addEventListener('DOMContentLoaded', main);
