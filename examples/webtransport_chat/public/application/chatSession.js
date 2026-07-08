import { createMessage, ChatMessage } from '../domain/message.js';
import { STATES, canTransition } from '../domain/connectionState.js';

function encode(message) {
  return new TextEncoder().encode(JSON.stringify(message.toJSON()));
}

function decode(bytes) {
  return ChatMessage.fromJSON(JSON.parse(new TextDecoder().decode(bytes)));
}

export class ChatSession {
  constructor(webTransportClient) {
    this.client = webTransportClient;
    this._state = STATES.DISCONNECTED;
    this.client.onReceive((bytes) => this._handleReceive(bytes));
  }

  get state() {
    return this._state;
  }

  _transitionTo(next) {
    if (canTransition(this._state, next)) {
      this._state = next;
    }
  }

  async connect() {
    this._transitionTo(STATES.CONNECTING);
    try {
      await this.client.connect();
      this._transitionTo(STATES.CONNECTED);
    } catch (err) {
      this._transitionTo(STATES.DISCONNECTED);
      throw err;
    }
  }

  async send(author, text) {
    const message = createMessage(author, text);
    await this.client.send(encode(message));
  }

  onMessageReceived(callback) {
    this._onMessage = callback;
  }

  _handleReceive(bytes) {
    if (this._onMessage) {
      this._onMessage(decode(bytes));
    }
  }
}
