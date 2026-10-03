// The e-mails madAuth asks for, as plain text and HTML. Edit the wording here, or use `locale` to translate.

export interface Mail {
  to: string;
  subject: string;
  text: string;
  html: string;
}

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function render(opts: { to: string; subject: string; intro: string; link: string; action: string; code?: string; outro: string }): Mail {
  const spacedCode = opts.code ? `${opts.code.slice(0, 3)} ${opts.code.slice(3)}` : undefined;
  const text = [
    opts.intro,
    '',
    `${opts.action}: ${opts.link}`,
    ...(spacedCode ? ['', `Or enter this code: ${spacedCode}`] : []),
    '',
    opts.outro,
  ].join('\n');
  const html = `<!doctype html>
<html><body style="font-family:system-ui,sans-serif;line-height:1.5;color:#111">
<p>${escapeHtml(opts.intro)}</p>
<p><a href="${escapeHtml(opts.link)}" style="display:inline-block;padding:10px 18px;background:#2563eb;color:#fff;border-radius:6px;text-decoration:none">${escapeHtml(opts.action)}</a></p>
${spacedCode ? `<p>Or enter this code:</p><p style="font-size:24px;font-weight:600;letter-spacing:4px">${spacedCode}</p>` : ''}
<p style="color:#555">${escapeHtml(opts.outro)}</p>
</body></html>`;
  return { to: opts.to, subject: opts.subject, text, html };
}

export function verifyEmailMail(to: string, site: string, link: string, code: string): Mail {
  return render({
    to,
    subject: `Confirm your e-mail address for ${site}`,
    intro: `Please confirm your e-mail address to finish creating your account on ${site}.`,
    action: 'Confirm e-mail address',
    link,
    code,
    outro: 'The link and the code are valid for 24 hours. If you did not create an account, ignore this e-mail.',
  });
}

export function resetPasswordMail(to: string, site: string, link: string, code: string): Mail {
  return render({
    to,
    subject: `Reset your password for ${site}`,
    intro: `Someone asked to reset the password of your account on ${site}.`,
    action: 'Choose a new password',
    link,
    code,
    outro: 'The link and the code are valid for 30 minutes. If you did not ask for this, ignore this e-mail; your password stays the same.',
  });
}

export function alreadyRegisteredMail(to: string, site: string, link: string): Mail {
  return render({
    to,
    subject: `You already have an account on ${site}`,
    intro: `Someone tried to create an account on ${site} with this e-mail address, but you already have one.`,
    action: `Sign in to ${site}`,
    link,
    outro: 'If you forgot your password, use "Forgot password?" when signing in. If this was not you, ignore this e-mail.',
  });
}
