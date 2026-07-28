// All DOM manipulation lives here; nothing else touches document/HTMLElement.
// Ported from examples/webtransport_chat/public/infrastructure/domRenderer.js.

export interface DomRendererElements {
  messageListEl: HTMLElement;
  statusEl: HTMLElement;
  formEl: HTMLFormElement;
  textInputEl: HTMLInputElement;
  authorInputEl: HTMLInputElement;
  certHashInputEl: HTMLInputElement;
  urlInputEl: HTMLInputElement;
  connectButtonEl: HTMLButtonElement;
}

export class DomRenderer {
  #els: DomRendererElements;

  constructor(els: DomRendererElements) {
    this.#els = els;
  }

  appendMessage(author: string, text: string, timestamp = Date.now()): void {
    const li = document.createElement("li");
    const time = new Date(timestamp).toLocaleTimeString();
    li.textContent = `[${time}] ${author}: ${text}`;
    this.#els.messageListEl.appendChild(li);
    this.#els.messageListEl.scrollTop = this.#els.messageListEl.scrollHeight;
  }

  setConnectionStatus(stateString: string): void {
    this.#els.statusEl.textContent = stateString;
    this.#els.statusEl.className = `status status-${stateString}`;
  }

  onFormSubmit(callback: (text: string) => void): void {
    this.#els.formEl.addEventListener("submit", (event) => {
      event.preventDefault();
      const text = this.#els.textInputEl.value;
      if (text.trim().length === 0) return;
      callback(text);
      this.#els.textInputEl.value = "";
    });
  }

  onConnectClick(callback: () => void): void {
    this.#els.connectButtonEl.addEventListener("click", () => callback());
  }

  getAuthorInput(): string {
    return this.#els.authorInputEl.value.trim();
  }

  getUrlInput(): string {
    return this.#els.urlInputEl.value.trim();
  }

  getCertHashInput(): string[] {
    return this.#els.certHashInputEl.value
      .split(",")
      .map((h) => h.trim())
      .filter((h) => h.length > 0);
  }
}
