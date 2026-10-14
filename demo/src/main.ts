import {
  Authenticator,
  EmailLink,
  GitHub,
  GoogleFedcm,
  GoogleRedirect,
  Madauth,
  Passkey,
  Password,
  type DeleteAccountOptions,
  type MadauthUser,
  type MethodsToSet,
  type Settings,
} from '@madauth/web';

const $ = <T extends HTMLElement = HTMLElement>(selector: string) => document.querySelector<T>(selector)!;

// --- Two demos: Google sign-in in the browser (One Tap / FedCM), or through the server (the redirect flow) ---

// `?google=redirect` picks the server-side flow; the links in #flow switch between the two. The redirect
// brings the browser back to this URL, so the choice survives it.
const flow = new URLSearchParams(location.search).get('google') === 'redirect' ? 'redirect' : 'fedcm';

for (const link of document.querySelectorAll<HTMLAnchorElement>('#flow a')) {
  if (link.dataset.flow === flow) link.setAttribute('aria-current', 'page');
}
for (const description of document.querySelectorAll<HTMLElement>('.flow-description')) {
  if (description.dataset.flow !== flow) continue;
  // Said as well as shown: aria-current on a paragraph is not announced.
  description.setAttribute('aria-current', 'true');
  description.querySelector('strong')!.insertAdjacentText('afterend', ' (current)');
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

// A method switched off is a valid setting and gets no note; one the server lacks the configuration for
// does. Visitors can only tell that for the redirect flow (Google on, without a client secret); an admin's
// settings tell it for every method.
const configGaps = { visitor: false, admin: { google: false, github: false } };
function showNotes(): void {
  $('#flow-note').hidden = !(flow === 'redirect' && (configGaps.visitor || configGaps.admin.google));
  $('#github-note').hidden = !configGaps.admin.github;
}

// No serverUrl: Vite proxies /auth to the madAuth server, so it is on this page's origin. GitHub is left out
// when the server has no OAuth App for it or an admin has it off, the authenticator app when the server has it switched off (no
// policy asks for it, and it signs in nobody alone), and the e-mail link when the server's webhook doesn't
// send its e-mails or an admin has it off.
void Madauth.initialize({ providers: [google, new GitHub(), new Password(), new Passkey(), new Authenticator(), new EmailLink()] }).then(async (result) => {
  // Back from adding Google or GitHub in the dialog's list of methods: below "Manage Sign-In Methods".
  if (result.linked) showOutput($('#methods-output'), `Back from linking ${result.linked}`, result);
  // GoogleRedirect is left out when Google is off or has no client secret; GET /auth/config tells which.
  if (flow !== 'redirect' || !result.leftOut.includes('google')) return;
  const config = await fetch(new URL('/auth/config', location.href).href)
    .then((res) => (res.ok ? (res.json() as Promise<{ google?: { codeFlow: boolean } | null }>) : undefined))
    .catch(() => undefined);
  configGaps.visitor = !!config?.google && !config.google.codeFlow;
  showNotes();
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
    // Nothing of the previous user stays on the page: the parameters, the responses, the settings, the app, the phone.
    resetExplorer();
    for (const box of [$('#authenticator-output'), $('#methods-output')]) {
      box.hidden = true;
      box.querySelector('pre')!.textContent = '';
    }
    $<HTMLInputElement>('#authenticator-code').value = '';
    showAuthenticator(false, false);
    showPhone(false, false);
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
  void refreshPhone();
  void refreshMethods();
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
  const status = await Madauth.authenticator.status();
  if (Madauth.currentUser?.id !== user?.id) return;
  const offered = status.isSuccess || status.error.code !== 'flow_not_enabled';
  $('#authenticator-status').textContent = !status.isSuccess
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
function codeOptions(typed = $<HTMLInputElement>('#authenticator-code').value): { code: string } | { recoveryCode: string } {
  const value = typed.trim();
  return value.includes('-') || value.length > 7 ? { recoveryCode: value } : { code: value.replace(/\s/g, '') };
}

// --- The phone for SMS codes, a second factor next to the app ---

/** Shows whether the signed-in user has a phone number, and the buttons that apply. */
async function refreshPhone(): Promise<void> {
  const user = Madauth.currentUser;
  const status = await Madauth.sms.status();
  if (Madauth.currentUser?.id !== user?.id) return;
  const offered = status.isSuccess || status.error.code !== 'flow_not_enabled';
  $('#sms-status').textContent = !status.isSuccess
    ? status.error.code === 'flow_not_enabled'
      ? 'Not offered by this madAuth server: SMS codes are switched off.'
      : status.error.message
    : status.enabled
      ? `Phone ${status.phone}.`
      : 'No phone number.';
  showPhone(status.isSuccess && status.enabled, offered);
}

function showPhone(on: boolean, offered: boolean): void {
  $('[data-call="setUpSms"]').hidden = !offered;
  $('[data-call="setUpSms"]').textContent = on ? 'Madauth.setUpSms() (replace)' : 'Madauth.setUpSms()';
  $('[data-call="removeSms"]').hidden = !on;
}

// --- The user's sign-in methods ---

const methodNames: Record<string, string> = { google: 'Google', github: 'GitHub', password: 'password', authenticator: 'authenticator app', 'email-link': 'e-mail link', passkey: 'passkey' };

/** Shows how the signed-in user signs in, and whether passkeys can be added. */
async function refreshMethods(): Promise<void> {
  const user = Madauth.currentUser;
  const list = await Madauth.methods.list();
  if (Madauth.currentUser?.id !== user?.id) return;
  $('#methods-status').textContent = !list.isSuccess
    ? list.error.message
    : list.methods.map((m) => (m.method === 'passkey' ? `passkey "${m.name}"` : methodNames[m.method]) + (m.signIn ? '' : ' (second factor only)')).join(', ') || 'None.';
  $('[data-call="setUpPasskey"]').hidden = !Madauth.passkey.available;
}

// --- The authenticator and phone calls in the account section: each shows what it resolved to below the buttons ---

const asText = (result: unknown) => (typeof result === 'string' ? result : JSON.stringify(result, null, 2));

/** Shows what a call resolved to in a response box: the authenticator app's, or the one below "Manage Sign-In Methods". */
function showOutput(box: HTMLElement, label: string, result: unknown): void {
  box.hidden = false;
  box.querySelector('pre')!.textContent = `${label}\n${asText(result)}`;
}

const accountCalls: Record<string, () => Promise<unknown>> = {
  // The dialog lists the user's methods, adds and removes them; it may ask the user to sign in again first.
  manageSignInMethods: () => Madauth.manageSignInMethods().then(async (result) => (await Promise.all([refreshMethods(), refreshAuthenticator()]), result)),
  // The dialog asks for a name, then the browser creates the passkey.
  setUpPasskey: () => Madauth.setUpPasskey().then(async (result) => (await refreshMethods(), result)),
  // The dialog shows the QR code, asks for the first code and shows the recovery codes.
  setUpAuthenticator: () => Madauth.setUpAuthenticator().then(async (result) => (await refreshAuthenticator(), result)),
  newRecoveryCodes: () => Madauth.authenticator.newRecoveryCodes(codeOptions()).then(async (result) => (await refreshAuthenticator(), result)),
  removeAuthenticator: () => Madauth.authenticator.remove(codeOptions()).then(async (result) => (await refreshAuthenticator(), result)),
  // The dialog asks for the number, then for the code sent to it (and, replacing one, for a code to the current number first).
  setUpSms: () => Madauth.setUpSms().then(async (result) => (await refreshPhone(), result)),
  // Removing the number takes a code sent to it: send, ask for it, remove.
  removeSms: async () => {
    const sent = await Madauth.sms.send();
    if (!sent.isSuccess) return sent;
    const code = prompt(`The code we sent to ${sent.phone}:`);
    if (!code) return 'Cancelled.';
    return Madauth.sms.remove({ code: code.replace(/\s/g, '') }).then(async (result) => (await refreshPhone(), result));
  },
};

for (const button of document.querySelectorAll<HTMLButtonElement>('#account button[data-call]')) {
  button.addEventListener('click', async () => {
    // A result for a user who signed out meanwhile (it may hold recovery codes) is dropped.
    const user = Madauth.currentUser?.id;
    button.disabled = true;
    try {
      const result = await accountCalls[button.dataset.call!]();
      // Labelled with the call: the code of a button that has a name of its own too.
      const box = button.id === 'manage-methods' ? $('#methods-output') : $('#authenticator-output');
      if (Madauth.currentUser?.id === user) showOutput(box, (button.querySelector('code') ?? button).textContent, result);
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

/** A method of the explorer: what to send, built from the parameters (or a reason nothing can be sent yet), and the call. */
interface ApiMethod {
  build(values: Values): Args | string;
  call(args: Args): Promise<unknown>;
}

/** Pairs a builder with its call, so the arguments one builds are what the other takes. */
function api<A extends Args>(build: (values: Values) => A | string, call: (args: A) => Promise<unknown>): ApiMethod {
  return { build, call: (args) => call(args as A) };
}

type MethodId = 'google' | 'github' | 'password' | 'authenticator' | 'email-link' | 'passkey' | 'sms';
const ALL_METHODS = ['google', 'github', 'password', 'email-link', 'passkey', 'authenticator', 'sms'] as const;
/** The methods whose policy for a second factor can be set: those that sign in. */
const WITH_POLICY = ['google', 'github', 'password', 'email-link', 'passkey'] as const;
/** The methods that sign in on their own or are only a second factor, as the admin chooses. */
const EITHER = ['passkey', 'authenticator'] as const;
type WithPolicy = (typeof WITH_POLICY)[number];
type Either = (typeof EITHER)[number];
const methodBox = (method: MethodId) => $<HTMLInputElement>(`#method-${method}`);
const signInBox = (method: Either) => $<HTMLInputElement>(`#signin-${method}`);
const policySelect = (method: WithPolicy) => $<HTMLSelectElement>(`#policy-${method}`);
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
  // A method the server doesn't list (an older server) counts as not configured.
  for (const method of ALL_METHODS) {
    methodBox(method).checked = methods?.[method]?.enabled ?? false;
    methodBox(method).disabled = !methods?.[method]?.configured;
  }
  for (const method of EITHER) {
    signInBox(method).checked = methods?.[method]?.allowAsSignInMethod ?? false;
    signInBox(method).disabled = !methods?.[method]?.configured;
  }
  for (const method of WITH_POLICY) {
    policySelect(method).value = methods?.[method]?.secondFactor ?? 'none';
    policySelect(method).disabled = !methods?.[method]?.configured;
  }
  configGaps.admin = { google: !!methods && !methods.google?.configured, github: !!methods && !methods.github?.configured };
  showNotes();
  settingsLoaded = !!methods;
  $('#settings-unloaded').hidden = settingsLoaded;
  executeButton('setSettings').disabled = !settingsLoaded;
  renderRequest(methodRow('setSettings'));
  return result;
}

/** The list to send: what is checked is on, with both of its settings; the rest is off. */
function methodsToSet(): MethodsToSet {
  const set: MethodsToSet = {};
  for (const method of ALL_METHODS) {
    if (!methodBox(method).checked) continue;
    const signIn = method === 'sms' ? false : (EITHER as readonly string[]).includes(method) ? signInBox(method as Either).checked : true;
    const policy = signIn && (WITH_POLICY as readonly string[]).includes(method) ? (policySelect(method as WithPolicy).value as 'none' | 'optional' | 'required') : 'none';
    set[method] = { allowAsSignInMethod: signIn, secondFactor: policy };
  }
  return set;
}

/** The claims typed as JSON, or the reason they can't be sent. */
function parseClaims(text: string): { claims: Record<string, unknown> } | { error: string } {
  try {
    return { claims: JSON.parse(text) as Record<string, unknown> };
  } catch {
    return { error: 'The claims must be JSON, e.g. { "roles": ["admin"] }.' };
  }
}

const methods: Record<string, ApiMethod> = {
  getSession: api(
    () => undefined,
    () => Madauth.getSession(),
  ),
  sessionReady: api(
    () => undefined,
    () => Madauth.sessionReady(),
  ),
  // Once the authenticator app is set up, the server also wants a current code from it. One click would
  // be too easy on a public demo: the user, their claims and their sign-in methods go for good.
  deleteAccount: api(
    (values): DeleteAccountOptions | undefined => (authenticatorOn ? codeOptions(values.code) : undefined),
    async (code) =>
      confirm('Delete your account on this madAuth server? Your user, claims and sign-in methods are deleted for good.')
        ? Madauth.deleteAccount(code)
        : 'Cancelled.',
  ),
  getClaims: api(
    (values) => ({ email: values.email.trim() }),
    ({ email }) => Madauth.admin.getClaims(email),
  ),
  // Anything but an object of claims is answered by the server with invalid_claims.
  setClaims: api(
    (values) => {
      const parsed = parseClaims(values.claims);
      return 'error' in parsed ? parsed.error : { email: values.email.trim(), claims: parsed.claims };
    },
    ({ email, claims }) => Madauth.admin.setClaims(email, claims),
  ),
  getSettings: api(
    () => undefined,
    () => Madauth.admin.getSettings().then(showSettings),
  ),
  setSettings: api(
    () => (settingsLoaded ? { methods: methodsToSet() } : 'Call getSettings first.'),
    // A refused change (e.g. every method switched off) leaves the controls as the user set them.
    (list) => Madauth.admin.setSettings(list).then((result) => (result.isSuccess ? showSettings(result) : result)),
  ),
};

const methodRow = (id: string) => $<HTMLLIElement>(`.api-method[data-call="${id}"]`);
const executeButton = (id: string) => methodRow(id).querySelector<HTMLButtonElement>('.api-execute')!;
const paramValues = (row: HTMLElement): Values =>
  Object.fromEntries([...row.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('[data-param]')].map((field) => [field.dataset.param!, field.value]));

/** Shows the call the row would make now: the method, and its arguments as JSON. */
function renderRequest(row: HTMLElement): void {
  const built = methods[row.dataset.call!].build(paramValues(row));
  const text = typeof built === 'string' ? built : built === undefined ? '(no arguments)' : JSON.stringify(built, null, 2);
  row.querySelector('.api-request')!.textContent = `${row.querySelector('.api-row')!.textContent}\n${text}`;
}

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
    const method = methods[row.dataset.call!];
    const built = method.build(paramValues(row));
    if (typeof built === 'string') {
      response.parentElement!.hidden = false;
      response.textContent = built;
      return;
    }
    // One call at a time per row; the button says so meanwhile (its disabled state belongs to showSettings).
    const user = Madauth.currentUser?.id;
    row.dataset.busy = 'true';
    execute.setAttribute('aria-disabled', 'true');
    let result: unknown;
    try {
      result = await method.call(built);
    } finally {
      delete row.dataset.busy;
      execute.removeAttribute('aria-disabled');
    }
    // A result for the user who called: into the row. One that arrives after they signed out (deleteAccount,
    // or a sign-out meanwhile): below the sign-in button, so they still see it. One that arrives once
    // someone else is signed in: dropped, it is not theirs.
    if (Madauth.currentUser?.id === user) {
      response.parentElement!.hidden = false;
      response.textContent = asText(result);
      renderRequest(row);
    } else if (!Madauth.currentUser) {
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
