package shirooauth.shiro;

import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;

/**
 * @author guilherme.pacheco
 * @author ygor.santana
 */
public class TokenSessionManager extends DefaultWebSessionManager {

  public TokenSessionManager() {
    setSessionDAO(enterpriseCacheSessionDAO());
    setSessionIdCookie(sessionIdCookie());
    setGlobalSessionTimeout(1_800_000);
    setSessionIdCookieEnabled(true);
    setDeleteInvalidSessions(true);
  }


  private Cookie sessionIdCookie() {
    SimpleCookie cookie = new SimpleCookie("sid");
    cookie.setHttpOnly(true);
    cookie.setMaxAge(-1);
    cookie.setPath("/");
    return cookie;
  }

  private EnterpriseCacheSessionDAO enterpriseCacheSessionDAO() {
    EnterpriseCacheSessionDAO dao = new EnterpriseCacheSessionDAO();
    dao.setActiveSessionsCacheName("oauthActiveSessionsCache");
    dao.setSessionIdGenerator(new JavaUuidSessionIdGenerator());
    return dao;
  }

}
