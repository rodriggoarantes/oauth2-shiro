package shirooauth.shiro;

import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import shirooauth.token.Token;

public class TokenShiroAuthRealm extends AuthorizingRealm implements Authenticator {
  
  private static final Logger LOG = LoggerFactory.getLogger(TokenShiroAuthRealm.class);
  
  public TokenShiroAuthRealm() {
    LOG.debug("TokenShiroAuthRealm");
    
    setCachingEnabled(true);
    setAuthenticationCachingEnabled(true);
    setAuthenticationCacheName("authenticationCache");
    
    setAuthorizationCachingEnabled(true);
    setAuthorizationCacheName("authorizationCache");
  }
  
  @Override
  public boolean supports(AuthenticationToken token) {
      return token instanceof Token;
  }
  
  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    LOG.debug("doGetAuthorizationInfo");
    if (principals != null) {
      String login = String.valueOf(principals.getPrimaryPrincipal());
      return this.autorization(login);
    } else {
      throw new AuthorizationException("Acesso não autorizado");
    }
  }
  private AuthorizationInfo autorization(String logado) {
    SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
    Set<String> permissoes = new HashSet<>(0);
    permissoes.add("ADMIN");
    info.setStringPermissions(permissoes);
    return info;
  }
  
  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    LOG.debug("doGetAuthenticationInfo");
    
    try {
      Token userToken = (Token) token;
      String auth = String.valueOf(userToken.getAuthCode());
      
      LOG.debug("doGetAuthenticationInfo: token: {}", auth);
      
      String loginUser = "";
      return new SimpleAuthenticationInfo(loginUser, auth, getName());
      
    } catch (Exception ex) {
      throw new AuthenticationException(ex.getMessage(), ex);
    }
  }
  
  // ----------- interface ------------
  @Override
  public AuthenticationInfo authenticate(AuthenticationToken authenticationToken)
      throws AuthenticationException {
    LOG.debug("authenticate");
    
    SimpleAuthenticationInfo authentication = new SimpleAuthenticationInfo();
    return authentication;
  }
  
  

}
