/** The parts of Google Identity Services (`google.accounts.id`) that madAuth uses. */
export interface GoogleAccountsId {
  initialize(config: {
    client_id: string;
    nonce: string;
    callback: (response: { credential: string }) => void;
    use_fedcm_for_button?: boolean;
    itp_support?: boolean;
    context?: 'signin' | 'signup' | 'use';
  }): void;
  prompt(): void;
  renderButton(
    parent: HTMLElement,
    options: {
      type?: 'standard' | 'icon';
      theme?: 'outline' | 'filled_blue' | 'filled_black';
      size?: 'large' | 'medium' | 'small';
      text?: 'signin_with' | 'signup_with' | 'continue_with' | 'signin';
      shape?: 'rectangular' | 'pill' | 'circle' | 'square';
      logo_alignment?: 'left' | 'center';
      width?: number;
    },
  ): void;
  disableAutoSelect(): void;
  cancel(): void;
}

declare global {
  interface Window {
    google?: { accounts?: { id?: GoogleAccountsId } };
  }
}

export const GIS_SRC = 'https://accounts.google.com/gsi/client';

let loading: Promise<GoogleAccountsId> | undefined;

/** Loads Google Identity Services once. A failed load can be retried. */
export function loadGis(): Promise<GoogleAccountsId> {
  if (!loading) {
    const script = document.createElement('script');
    script.src = GIS_SRC;
    script.async = true;
    loading = new Promise<GoogleAccountsId>((resolve, reject) => {
      script.addEventListener('load', () => {
        const id = window.google?.accounts?.id;
        if (id) resolve(id);
        else reject(new Error(`${GIS_SRC} loaded but google.accounts.id is missing`));
      });
      script.addEventListener('error', () => reject(new Error(`could not load ${GIS_SRC}`)));
    });
    loading.catch(() => {
      loading = undefined;
      script.remove();
    });
    document.head.append(script);
  }
  return loading;
}

/** Test hook: forgets the loaded script. */
export function resetGisForTests(): void {
  loading = undefined;
  document.querySelectorAll(`script[src="${GIS_SRC}"]`).forEach((s) => s.remove());
}
