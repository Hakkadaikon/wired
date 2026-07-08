// All DOM manipulation lives here; nothing else touches document/HTMLElement.

export class DomRenderer {
  #messageListEl;
  #statusEl;
  #formEl;
  #textInputEl;
  #authorInputEl;
  #certHashInputEl;

  constructor({ messageListEl, statusEl, formEl, textInputEl, authorInputEl, certHashInputEl }) {
    this.#messageListEl = messageListEl;
    this.#statusEl = statusEl;
    this.#formEl = formEl;
    this.#textInputEl = textInputEl;
    this.#authorInputEl = authorInputEl;
    this.#certHashInputEl = certHashInputEl;
  }

  appendMessage(chatMessage) {
    const li = document.createElement('li');
    const time = new Date(chatMessage.timestamp).toLocaleTimeString();
    li.textContent = `[${time}] ${chatMessage.author}: ${chatMessage.text}`;
    this.#messageListEl.appendChild(li);
    this.#messageListEl.scrollTop = this.#messageListEl.scrollHeight;
  }

  setConnectionStatus(stateString) {
    this.#statusEl.textContent = stateString;
    this.#statusEl.className = `status status-${stateString}`;
  }

  onFormSubmit(callback) {
    this.#formEl.addEventListener('submit', (event) => {
      event.preventDefault();
      callback(this.#authorInputEl.value, this.#textInputEl.value);
      this.#textInputEl.value = '';
    });
  }

  getCertHashInput() {
    return this.#certHashInputEl.value.trim();
  }
}
