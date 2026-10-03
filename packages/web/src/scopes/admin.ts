import type { Result } from '../result.js';
import type { Core } from './core.js';

/**
 * Managing roles, for users with the role `admin`. The madAuth server keeps roles per e-mail address, so
 * they apply whichever way the owner of the address signs in. The first admin is made on the server:
 * `npx @madauth/server set-roles you@example.com admin`.
 */
export interface AdminApi {
  /** The roles of an e-mail address. Fails with `forbidden` for users without the role `admin`. */
  getRoles(email: string): Promise<Result<{ roles: string[] }>>;
  /**
   * Replaces the roles of an e-mail address; an empty list removes them. The address needs no account
   * yet. The change shows in a session the next time its app checks it (`Madauth.getSession`, or the next
   * page load). Fails with `forbidden`, `invalid_email` or `invalid_roles`.
   */
  setRoles(email: string, roles: string[]): Promise<Result<{ roles: string[] }>>;
}

export function createAdminApi(core: Core): AdminApi {
  async function call(action: 'get' | 'set', body: Record<string, unknown>): Promise<Result<{ roles: string[] }>> {
    const ready = await core.whenReady();
    if (!ready.isSuccess) return ready;
    const res = await core.request<{ roles: string[] }>(`/auth/admin/roles/${action}`, { method: 'POST', body });
    return res.ok ? { isSuccess: true, roles: res.data.roles } : { isSuccess: false, error: res.error };
  }

  return {
    getRoles: (email) => call('get', { email }),
    setRoles: (email, roles) => call('set', { email, roles }),
  };
}
