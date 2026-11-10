// The signed-in user's sessions: listing them, and ending one or all others. An ended session stops at its next
// renewal, within SESSION_TTL; `user.session_ended` tells backends that want it sooner. See sessions.ts.
import type { Context, Hono } from 'hono';
import type { AppContext } from '../app.js';
import { sessionInfo } from '../sessions.js';
import { body, error, isRecent, noSession, reauthRequired } from './helpers.js';

export const sessionNotFound = (c: Context): Response => error(c, 404, 'session_not_found', 'There is no such session, or it has ended already.');

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
    if (!(await isRecent(ctx, signIn))) return reauthRequired(c);
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
    if (!(await isRecent(ctx, signIn))) return reauthRequired(c);
    const { stored: user } = signIn;
    const ended = await ctx.sessions.endAll(user.id, user.sessionVersion, signIn.sessionId);
    // The session version goes up too, so sessions without a record (from before madAuth 0.7.5), the sign-ins that
    // wait for their second step and the OpenID Connect refresh tokens end as well. This session goes on with it, as
    // the same sign-in: new tokens and its record with the new version.
    const sessionVersion = user.sessionVersion + 1;
    await ctx.users.updateUser(user.id, { sessionVersion });
    await ctx.continueSession(c, signIn, sessionVersion);
    await ctx.sessionsEnded(user, ended, 'ended');
    return c.json({ ended: ended.length });
  });
}
