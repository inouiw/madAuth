import { LitElement, css, html } from 'lit';
import { loginMethods, type LoginMethod, type LoginMethodId } from './methods.js';

export interface SignedInDetail {
  method: LoginMethodId;
  user: { id: string; email?: string; name?: string };
}

/**
 * Modal sign-in dialog listing all madAuth login methods.
 *
 * @fires madauth-signed-in - A user signed in. `detail` is a {@link SignedInDetail}.
 * @fires madauth-cancel - The dialog was closed without signing in.
 *
 * @cssprop --madauth-primary - Accent color.
 * @cssprop --madauth-radius - Corner radius of the dialog and buttons.
 * @cssprop --madauth-font - Font family.
 *
 * @csspart dialog - The `<dialog>` element.
 * @csspart method - Each sign-in method button.
 */
export class MadauthLogin extends LitElement {
  static override properties = {
    heading: { type: String },
  };

  /** Title shown at the top of the dialog. */
  heading = 'Sign in';

  /** Opens the dialog as a modal. */
  async open(): Promise<void> {
    await this.updateComplete;
    this.dialog.showModal();
  }

  /** Closes the dialog without firing `madauth-cancel`. */
  close(): void {
    this.dialog.close('done');
  }

  private get dialog(): HTMLDialogElement {
    return this.renderRoot.querySelector('dialog')!;
  }

  private onDialogClose(): void {
    if (this.dialog.returnValue !== 'done') {
      this.dispatchEvent(new CustomEvent('madauth-cancel', { bubbles: true, composed: true }));
    }
    this.dialog.returnValue = '';
  }

  private onBackdropClick(e: MouseEvent): void {
    // Clicks on the backdrop target the <dialog> itself; clicks inside hit its children.
    if (e.target === this.dialog) this.dialog.close();
  }

  override render() {
    return html`
      <dialog part="dialog" @close=${this.onDialogClose} @click=${this.onBackdropClick}>
        <header>
          <h2>${this.heading}</h2>
          <button class="close" aria-label="Close" @click=${() => this.dialog.close()}>×</button>
        </header>
        <ul>
          ${loginMethods.map((m) => html`<li>${this.renderMethod(m)}</li>`)}
        </ul>
      </dialog>
    `;
  }

  private renderMethod(m: LoginMethod) {
    const comingSoon = m.status === 'coming-soon';
    return html`
      <button part="method" class="method" ?disabled=${comingSoon} data-method=${m.id}>
        <span class="text">
          <span class="label">${m.label}</span>
          <span class="description">${m.description}</span>
        </span>
        ${comingSoon ? html`<span class="badge">Coming soon</span>` : null}
      </button>
    `;
  }

  static override styles = css`
    :host {
      --_primary: var(--madauth-primary, #4f46e5);
      --_radius: var(--madauth-radius, 12px);
      font-family: var(--madauth-font, system-ui, sans-serif);
    }

    dialog {
      width: min(420px, calc(100vw - 32px));
      box-sizing: border-box;
      padding: 24px;
      border: none;
      border-radius: var(--_radius);
      box-shadow: 0 20px 50px rgb(0 0 0 / 0.25);
      color: #1f2937;
      background: #fff;
      font: inherit;
    }

    dialog::backdrop {
      background: rgb(15 23 42 / 0.5);
    }

    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }

    h2 {
      margin: 0;
      font-size: 1.25rem;
    }

    .close {
      border: none;
      background: none;
      font-size: 1.5rem;
      line-height: 1;
      cursor: pointer;
      color: inherit;
      padding: 4px 8px;
      border-radius: 6px;
    }

    ul {
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 8px;
    }

    .method {
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 14px;
      text-align: left;
      font: inherit;
      color: inherit;
      background: #fff;
      border: 1px solid #e5e7eb;
      border-radius: calc(var(--_radius) - 4px);
      cursor: pointer;
    }

    .method:not(:disabled):hover {
      border-color: var(--_primary);
    }

    .method:disabled {
      cursor: not-allowed;
      background: #f9fafb;
    }

    .text {
      display: grid;
      gap: 2px;
    }

    .label {
      font-weight: 600;
    }

    .description {
      font-size: 0.85rem;
      color: #6b7280;
    }

    .badge {
      flex-shrink: 0;
      font-size: 0.75rem;
      padding: 2px 8px;
      border-radius: 999px;
      color: var(--_primary);
      background: color-mix(in srgb, var(--_primary) 12%, transparent);
    }

    @media (prefers-color-scheme: dark) {
      dialog {
        color: #e5e7eb;
        background: #1f2937;
      }
      .method {
        background: #1f2937;
        border-color: #374151;
      }
      .method:disabled {
        background: #111827;
      }
      .description {
        color: #9ca3af;
      }
      .badge {
        color: color-mix(in srgb, var(--_primary) 40%, #fff);
        background: color-mix(in srgb, var(--_primary) 25%, transparent);
      }
    }
  `;
}

declare global {
  interface HTMLElementTagNameMap {
    'madauth-login': MadauthLogin;
  }
  interface HTMLElementEventMap {
    'madauth-signed-in': CustomEvent<SignedInDetail>;
    'madauth-cancel': CustomEvent<void>;
  }
}
