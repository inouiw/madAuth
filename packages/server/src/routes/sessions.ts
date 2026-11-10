// The signed-in user's sessions: listing them, and ending one or all others. An ended session stops at its next
// renewal, within SESSION_TTL; `user.session_ended` tells backends that want it sooner. See sessions.ts.
import type { Context, Hono } from 'hono';
import type { AppContext, SignIn } from '../app.js';
import { sessionInfo } from '../sessions.js';
import { RECENT_SIGN_IN_MS, body, error, noSession, reauthRequired } from './helpers.js';

export const sessionNotFound = (c: Context): Response => error(c, 404, 'session_not_found', 'There is no such session, or it has ended already.');

/** Whether the user signed in within RECENT_SIGN_IN_MS, as a sensitive change needs. */
const recent = (signIn: SignIn): boolean => signIn.signedInAt !== null && Date.now() - signIn.signedInAt <= RECENT_SIGN_IN_MS;

export function sessionRoutes(app: Hono, ctx: AppContext): void {
  // The current session first, then by the latest activity.
  app.get('/auth/sessions', async (c) => {
    const signIn = await ctx.currentSignIn(c);
    if (!signIn) return noSession(c);
    const list = (await ctx.sessions.list(signIn.user.id, signIn.stored.sessionVersion)).map((session) => sessionInfo(session, signIn.sessionId));
    return c.json({ sessions: [...list.filter((s) => s.current), ...list.filter((s) => !s.current)] });
  });

  // Like changing a method, only right after signing in: a session someone took over can't end the user's own.
  app.post('/auth/sessions/end', async (c) => {
    const signIn = await ctx.currentSignIn(c);
    if (!signIn) return noSession(c);
    if (!recent(signIn)) return reauthRequired(c);
    const { id } = await body(c);
    const ended = typeof id === 'string' && id ? await ctx.sessions.end(signIn.user.id, id) : null;
    if (!ended) return sessionNotFound(c);
    await ctx.sessionsEnded(signIn.stored, [ended], 'ended');
    // Ending the session of this browser signs it out at once.
    if (ended.id === signIn.sessionId) await ctx.signOut(c);
    return c.body(null, 204);
  });

  app.post('/auth/sessions/end-others', async (c) => {
    const signIn = await ctx.currentSignIn(c);
    if (!signIn) return noSession(c);
    if (!recent(signIn)) return reauthRequired(c);
    const ended = await ctx.sessions.endAll(signIn.user.id, signIn.stored.sessionVersion, signIn.sessionId);
    await ctx.sessionsEnded(signIn.stored, ended, 'ended');
    return c.json({ ended: ended.length });
  });
}
