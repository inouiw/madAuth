import { GoogleFedcm, GoogleRedirect, Madauth, Password, Totp, type DeleteAccountOptions, type MadauthUser, type MethodsToSet, type Settings } from '@madauth/web';

const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;

// --- Two demos: Google sign-in in the browser (One Tap / FedCM), or through the server (the redirect flow) ---

// `?google=redirect` picks the server-side flow; the links in #flow switch between the two. The redirect
// brings the browser back to this URL, so the choice survives it.
const flow = new URLSearchParams(location.search).get('google') === 'redirect' ? 'redirect' : 'fedcm';

for (const link of document.querySelectorAll<HTMLAnchorElement>('#flow a')) {
  if (link.dataset.flow === flow) link.setAttribute('aria-current', 'page');
}
for (const description of document.querySelectorAll<HTMLElement>('.flow-description')) {
  if (description.dataset.flow === flow) description.setAttribute('aria-current', 'true');
}

// The info buttons: each shows and hides the explanation it controls.
for (const button of document.querySelectorAll<HTMLButtonElement>('button.info')) {
  const text = document.getElementById(button.getAttribute('aria-controls')!)!;
  button.addEventListener('click', () => {
    text.hidden = !text.hidden;
    button.setAttribute('aria-expanded', String(!text.hidden));
  });
}

const google = flow === 'redirect' ? new GoogleRedirect() : new GoogleFedcm();

// The public demo gives no visitor the role admin: an admin could change every visitor's claims and switch
// sign-in methods off for everyone. Visitors are told so, and how to try the admin API on their machine.
const { hostname } = location;
$('[data-hosted]').hidden = !(hostname === 'madauth.com' || hostname.endsWith('.madauth.com'));

// No serverUrl: Vite proxies /auth to the madAuth server, so it is on this page's origin. The authenticator
// app is left out when the server has it switched off (no policy asks for it, and it signs in nobody alone).
void Madauth.initialize({ providers: [google, new Password(), new Totp()] }).then((result) => {
  // The server offers the redirect flow only with a client secret (and Google switched on); otherwise
  // initialize left GoogleRedirect out and the dialog has no Google button.
  if (flow === 'redirect' && result.leftOut.includes('google')) $('#flow-note').hidden = false;
});
Madauth.onAuthStateChanged(handleAuthStateChanged);

$('#sign-in').addEventListener('click', () => void Madauth.signIn());
$('#sign-out').addEventListener('click', () => void Madauth.signOut());

function handleAuthStateChanged(user: MadauthUser | null): void {
  $('#sign-in').hidden = !!user;
  $('#account').hidden = !user;
  $('#api').hidden = !user;
  $('#user-name').textContent = user?.name ?? user?.id ?? '';
  $('#user-email').textContent = user?.email ?? '';
  const avatar = $<HTMLImageElement>('#avatar');
  avatar.hidden = !user?.picture;
  if (user?.picture) avatar.src = user.picture;
  // What admins attached to the user, e.g. { roles: ['admin'] }; the session token carries it to your backends too.
  $('#claims').textContent = user?.claims ? JSON.stringify(user.claims, null, 2) : 'none';
  // How the session was authenticated, e.g. pwd and otp: a backend can ask for otp before a sensitive action.
  $('#amr').textContent = user?.amr?.join(', ') ?? '';

  if (!user) {
    // Nothing of the previous user stays on the page: the parameters, the responses, the settings, the app.
    resetExplorer();
    $('#totp-output').hidden = true;
    output.textContent = '';
    $<HTMLInputElement>('#totp-code').value = '';
    showAuthenticator(false, false);
    settingsLoadedFor = undefined;
    showSettings(null);
    return;
  }
  $('#last-response').hidden = true;
  // The admin calls start with the signed-in user's own address.
  for (const field of document.querySelectorAll<HTMLInputElement>('[data-param="email"]')) {
    if (!field.value) field.value = user.email ?? '';
  }
  $('#admin-note').hidden = isAdmin(user);
  void refreshAuthenticator();
  // An admin sees the server's settings in the controls before they can send them back.
  if (isAdmin(user) && settingsLoadedFor !== user.id) {
    settingsLoadedFor = user.id;
    void Madauth.admin.getSettings().then((result) => {
      // Not if they signed out meanwhile: the next user must not see them.
      if (Madauth.currentUser?.id === user.id) showSettings(result);
    });
  }
}

const isAdmin = (user: MadauthUser) => Array.isArray(user.claims?.roles) && user.claims.roles.includes('admin');

// --- The authenticator app of the signed-in user ---

/** Whether the signed-in user has the app; decides which buttons make sense, and whether deleting the account takes a code. */
let authenticatorOn = false;

/** Shows whether the user has the app, and the buttons that apply. */
async function refreshAuthenticator(): Promise<void> {
  const user = Madauth.currentUser;
  const status = await Madauth.totp.status();
  if (Madauth.currentUser?.id !== user?.id) return;
  const offered = status.isSuccess || status.error.code !== 'flow_not_enabled';
  $('#totp-status').textContent = !status.isSuccess
    ? status.error.code === 'flow_not_enabled'
      ? 'Not offered by this madAuth server: no sign-in method asks for it, and it signs in nobody on its own.'
      : status.error.message
    : status.enabled
      ? `Set up, ${status.recoveryCodesLeft} recovery codes left.`
      : 'Not set up.';
  showAuthenticator(status.isSuccess && status.enabled, offered);
}

/** Shows what applies with or without the app: the code fields, the buttons, and deleteAccount's arguments. */
function showAuthenticator(on: boolean, offered: boolean): void {
  authenticatorOn = on;
  $('.authenticator .code-field').hidden = !on;
  $('[data-needs-authenticator]').hidden = !on;
  $('[data-call="setUpAuthenticator"]').hidden = !offered;
  $('[data-call="newRecoveryCodes"]').hidden = !on;
  $('[data-call="removeAuthenticator"]').hidden = !on;
  // Once the app is set up, deleting the account takes a code: the row's request changes with it.
  renderRequest(methodRow('deleteAccount'));
}

/** A code as typed, next to the buttons or as a parameter: a 6-digit code from the app, or a recovery code (with a dash). */
function codeOptions(typed = $<HTMLInputElement>('#totp-code').value): { code: string } | { recoveryCode: string } {
  const value = typed.trim();
  return value.includes('-') || value.length > 7 ? { recoveryCode: value } : { code: value.replace(/\s/g, '') };
}

// --- The authenticator calls in the account section: each shows what it resolved to below the buttons ---

const output = $('#output');

function showOutput(label: string, result: unknown): void {
  $('#totp-output').hidden = false;
  output.textContent = `${label}\n${typeof result === 'string' ? result : JSON.stringify(result, null, 2)}`;
}

const accountCalls: Record<string, () => Promise<unknown>> = {
  // The dialog shows the QR code, asks for the first code and shows the recovery codes.
  setUpAuthenticator: () => Madauth.setUpAuthenticator().then(async (result) => (await refreshAuthenticator(), result)),
  newRecoveryCodes: () => Madauth.totp.newRecoveryCodes(codeOptions()).then(async (result) => (await refreshAuthenticator(), result)),
  removeAuthenticator: () => Madauth.totp.remove(codeOptions()).then(async (result) => (await refreshAuthenticator(), result)),
};

for (const button of document.querySelectorAll<HTMLButtonElement>('.authenticator button[data-call]')) {
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      showOutput(button.textContent, await accountCalls[button.dataset.call!]());
    } finally {
      button.disabled = false;
    }
  });
}

// --- The API explorer: the rest of what a signed-in user can call, a method per row ---
//
// Each row in #api names a method (data-call); its detail holds the description and the parameters (inputs
// with data-param). This adds the request box (the call with its arguments, as JSON), the Execute button
// and the response box to every row, keeps the request up to date, and runs the call.

/** The parameters as typed, by name. */
type Values = Record<string, string>;
/** The arguments a call gets, by name, or undefined for none; built from the parameters. */
type Args = Record<string, unknown> | undefined;

const methodBox = (method: 'google' | 'password' | 'totp') => $<HTMLInputElement>(`#method-${method}`);
const policySelect = (method: 'google' | 'password') => $<HTMLSelectElement>(`#policy-${method}`);
/** The user whose sign-in loaded the settings, so a claims change (which also notifies) doesn't load them again. */
let settingsLoadedFor: string | undefined;
/** Whether the controls show the server's settings; only then may setSettings send them. */
let settingsLoaded = false;

/**
 * Shows the server's settings in the controls and lets them be sent back; until then (or with null) the
 * controls are empty and setSettings is off, so the page never sends defaults the server doesn't have. A
 * method the server is not configured for can't be switched on.
 */
function showSettings<T extends Awaited<ReturnType<typeof Madauth.admin.getSettings>> | null>(result: T): T {
  const methods: Settings['methods'] | undefined = result?.isSuccess ? result.methods : undefined;
  for (const method of ['google', 'password', 'totp'] as const) {
    methodBox(method).checked = methods?.[method].enabled ?? false;
    methodBox(method).disabled = !methods?.[method].configured;
  }
  for (const method of ['google', 'password'] as const) {
    policySelect(method).value = methods?.[method].secondFactor ?? 'none';
    policySelect(method).disabled = !methods?.[method].configured;
  }
  settingsLoaded = !!methods;
  $('#settings-unloaded').hidden = settingsLoaded;
  executeButton('setSettings').disabled = !settingsLoaded;
  renderRequest(methodRow('setSettings'));
  return result;
}

/** The list to send: what is checked is on, with the policy next to it; the rest is off. */
function methodsToSet(): MethodsToSet {
  const policy = (method: 'google' | 'password') => ({ secondFactor: policySelect(method).value as 'none' | 'optional' | 'required' });
  return {
    google: methodBox('google').checked ? policy('google') : false,
    password: methodBox('password').checked ? policy('password') : false,
    totp: methodBox('totp').checked,
  };
}

/** The claims typed as JSON, or the reason they can't be sent. */
function parseClaims(text: string): { claims: Record<string, unknown> } | { error: string } {
  try {
    return { claims: JSON.parse(text) as Record<string, unknown> };
  } catch {
    return { error: 'The claims must be JSON, e.g. { "roles": ["admin"] }.' };
  }
}

/** The arguments of each call, from its parameters. A string is a reason nothing can be sent yet. */
const args: Record<string, (values: Values) => Args | string> = {
  getSession: () => undefined,
  sessionReady: () => undefined,
  // Once the authenticator app is set up, the server also wants a current code from it.
  deleteAccount: (values) => (authenticatorOn ? codeOptions(values.code) : undefined),
  getClaims: (values) => ({ email: values.email.trim() }),
  setClaims: (values) => {
    const parsed = parseClaims(values.claims);
    return 'error' in parsed ? parsed.error : { email: values.email.trim(), claims: parsed.claims };
  },
  getSettings: () => undefined,
  setSettings: () => (settingsLoaded ? { methods: methodsToSet() } : 'Call getSettings first.'),
};

/** The calls, each with the arguments its entry in `args` built. */
const calls: Record<string, (args: Args) => Promise<unknown>> = {
  getSession: () => Madauth.getSession(),
  sessionReady: () => Madauth.sessionReady(),
  // One click would be too easy on a public demo: the user, their claims and their sign-in methods go for good.
  deleteAccount: async (code) =>
    confirm('Delete your account on this madAuth server? Your user, claims and sign-in methods are deleted for good.')
      ? Madauth.deleteAccount(code as DeleteAccountOptions | undefined)
      : 'Cancelled.',
  getClaims: (by) => Madauth.admin.getClaims(String(by?.email)),
  // Anything but an object of claims is answered by the server with invalid_claims.
  setClaims: (to) => Madauth.admin.setClaims(String(to?.email), to?.claims as Record<string, unknown>),
  getSettings: () => Madauth.admin.getSettings().then(showSettings),
  setSettings: (list) =>
    Madauth.admin
      .setSettings(list as { methods: MethodsToSet })
      // A refused change (e.g. every method switched off) leaves the controls as the user set them.
      .then((result) => (result.isSuccess ? showSettings(result) : result)),
};

const methodRow = (id: string) => $<HTMLLIElement>(`.api-method[data-call="${id}"]`);
const executeButton = (id: string) => methodRow(id).querySelector<HTMLButtonElement>('.api-execute')!;
const paramValues = (row: HTMLElement): Values =>
  Object.fromEntries([...row.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('[data-param]')].map((field) => [field.dataset.param!, field.value]));

/** Shows the call the row would make now: the method, and its arguments as JSON. */
function renderRequest(row: HTMLElement): void {
  const built = args[row.dataset.call!](paramValues(row));
  const text = typeof built === 'string' ? built : built === undefined ? '(no arguments)' : JSON.stringify(built, null, 2);
  row.querySelector('.api-request')!.textContent = `${row.querySelector('.api-row')!.textContent}\n${text}`;
}

const asText = (result: unknown) => (typeof result === 'string' ? result : JSON.stringify(result, null, 2));

for (const row of document.querySelectorAll<HTMLLIElement>('.api-method')) {
  const toggle = row.querySelector<HTMLButtonElement>('.api-row')!;
  const detail = row.querySelector<HTMLElement>('.api-detail')!;
  detail.insertAdjacentHTML(
    'beforeend',
    `<div class="api-box"><span class="caption">Request</span><pre class="api-request"></pre></div>
     <p class="buttons"><button type="button" class="api-execute">Execute</button></p>
     <div class="api-box" hidden><span class="caption">Response</span><pre class="api-response" role="status"></pre></div>`,
  );
  const response = detail.querySelector<HTMLElement>('.api-response')!;
  toggle.addEventListener('click', () => {
    detail.hidden = !detail.hidden;
    toggle.setAttribute('aria-expanded', String(!detail.hidden));
    if (!detail.hidden) renderRequest(row);
  });
  // The request follows the parameters as they are typed or picked. The admin calls share the address:
  // what is typed into one e-mail field is what the other targets too, so a lookup and a change can't drift apart.
  detail.addEventListener('input', (e) => {
    const field = e.target as HTMLInputElement;
    if (field.dataset.param === 'email') {
      for (const other of document.querySelectorAll<HTMLInputElement>('[data-param="email"]')) {
        if (other !== field) {
          other.value = field.value;
          renderRequest(other.closest('.api-method')!);
        }
      }
    }
    renderRequest(row);
  });
  detail.addEventListener('change', () => renderRequest(row));
  const execute = detail.querySelector<HTMLButtonElement>('.api-execute')!;
  execute.addEventListener('click', async () => {
    if (row.dataset.busy) return;
    const id = row.dataset.call!;
    const built = args[id](paramValues(row));
    if (typeof built === 'string') {
      response.parentElement!.hidden = false;
      response.textContent = built;
      return;
    }
    // One call at a time per row. A result that arrives after the user signed out (deleteAccount, or a
    // sign-out meanwhile) must not land in the next user's page: it goes below the sign-in button instead.
    const user = Madauth.currentUser?.id;
    row.dataset.busy = 'true';
    let result: unknown;
    try {
      result = await calls[id](built);
    } finally {
      delete row.dataset.busy;
    }
    if (Madauth.currentUser?.id === user) {
      response.parentElement!.hidden = false;
      response.textContent = asText(result);
      renderRequest(row);
    } else {
      $('#last-response').hidden = false;
      $('#last-response pre').textContent = `${toggle.textContent}\n${asText(result)}`;
    }
  });
}

/** Closes every row and clears what was typed and answered: nothing of the previous user stays for the next. */
function resetExplorer(): void {
  for (const row of document.querySelectorAll<HTMLLIElement>('.api-method')) {
    row.querySelector<HTMLElement>('.api-detail')!.hidden = true;
    row.querySelector('.api-row')!.setAttribute('aria-expanded', 'false');
    for (const field of row.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('[data-param]')) field.value = field.defaultValue;
    const response = row.querySelector<HTMLElement>('.api-response')!;
    response.textContent = '';
    response.parentElement!.hidden = true;
  }
}

// --- Theme ---

type Theme = 'light' | 'dark';

const themeToggle = $<HTMLButtonElement>('#theme-toggle');

function setTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  themeToggle.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`);
}

// Start with the system preference; the button then overrides it for this page.
setTheme(matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

themeToggle.addEventListener('click', () => {
  setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
});
