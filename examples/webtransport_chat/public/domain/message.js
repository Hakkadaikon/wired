// ChatMessage value object. Immutable.
const MAX_TEXT_LENGTH = 500;

function isBlank(s) {
  return typeof s !== 'string' || s.trim().length === 0;
}

export class ChatMessage {
  constructor(author, text, timestamp) {
    if (isBlank(author)) {
      throw new Error('author must not be empty');
    }
    if (isBlank(text)) {
      throw new Error('text must not be empty');
    }
    if (text.length > MAX_TEXT_LENGTH) {
      throw new Error(`text must not exceed ${MAX_TEXT_LENGTH} characters`);
    }
    this.author = author;
    this.text = text;
    this.timestamp = timestamp;
    Object.freeze(this);
  }

  toJSON() {
    return { a: this.author, t: this.text, ts: this.timestamp };
  }

  static fromJSON(obj) {
    return createMessage(obj.a, obj.t, obj.ts);
  }
}

export function createMessage(author, text, timestamp = Date.now()) {
  return new ChatMessage(author, text, timestamp);
}
