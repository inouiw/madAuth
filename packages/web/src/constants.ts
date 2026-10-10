/** Hash parameter the server uses to report a failed redirect sign-in (`#madauth_error=<code>`). */
export const REDIRECT_ERROR_PARAM = 'madauth_error';
/** Hash parameter that says what a redirect sign-in still needs (`#madauth_next=totp` or `totp-setup`). */
export const REDIRECT_NEXT_PARAM = 'madauth_next';

/** Hash parameters of the links in madAuth's e-mails (`#madauth_verify=<token>`, `#madauth_reset=<token>`). */
export const VERIFY_LINK_PARAM = 'madauth_verify';
export const RESET_LINK_PARAM = 'madauth_reset';

/**
 * Cookie in which the server tells when the session expires (seconds since 1970). It stays for as long as
 * the session can be renewed, so a time in the past means "renew before use".
 */
export const EXPIRY_COOKIE = 'madauth_session_expires';
