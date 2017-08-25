package shirooauth.shiro;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ParameterStyle;
import org.apache.oltu.oauth2.rs.request.OAuthAccessResourceRequest;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import shirooauth.domain.Token;

public class OAuth2AuthenticationFilter extends AuthenticatingFilter {
  
  private static final Logger LOG = LoggerFactory.getLogger(OAuth2AuthenticationFilter.class);
  
  public OAuth2AuthenticationFilter() {
    LOG.debug("OAuth2AuthenticationFilter");
  }

  @Override
  protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
    LOG.debug("createToken:Shiro");
    
    final HttpServletRequest httpRequest = (HttpServletRequest) request;
    
    final Token token = new Token();
    try {
      
      OAuthAccessResourceRequest oauthRequest = new OAuthAccessResourceRequest(httpRequest, ParameterStyle.HEADER);
      String accessOAuth = oauthRequest.getAccessToken();
      
      token.setAuthCode(accessOAuth);
      
    } catch (Exception e) {
      LOG.error("Erro ao converter request para OAuth");
    }
    
    return token;
  }

  @Override
  protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
    LOG.debug("onAccessDenied");
    
    final String token;
    final HttpServletResponse httpResponse = WebUtils.toHttp(response);
    
    try {
      
      OAuthAccessResourceRequest oauthRequest = new OAuthAccessResourceRequest((HttpServletRequest) request, ParameterStyle.HEADER);
      token = oauthRequest.getAccessToken();
      
      Subject subject = getSubject(request, response);
      LOG.debug("onAccessDenied:subject {}", subject.isAuthenticated());
      
      LOG.debug("onAccessDenied:token {}", token);
      if(!StringUtils.isEmpty(token) && token.equals("08972624e61497237836c5b4717cef2")) {
        // executa shiro login
        final boolean loggedIn = executeLogin(request, response);
        LOG.debug("onAccessDenied:loggedIntoken {}", loggedIn);
        return loggedIn;
      } else {
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      }
      
    } catch (Exception e) {
      LOG.error("Erro ao obter OAuth Token do Header");
      httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    }
    
    return false;
  }
  
  @Override
  protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
      LOG.debug("isAccessAllowed");
      
      try {
        final OAuthTokenRequest oauthRequest = new OAuthTokenRequest((HttpServletRequest) request);
        
        //build response according to response_type
        final String responseType = oauthRequest.getGrantType();
        
        LOG.debug("isAccessAllowed:responseType {}", responseType);
        if ( (GrantType.PASSWORD.toString()).equalsIgnoreCase(responseType) ) {
          
          // TODO validar client_id e client_secret
          oauthRequest.getClientId();
          oauthRequest.getClientSecret();
          
          return true;
        }
        
      } catch (Exception e) {
        LOG.warn("REQUISICAO NÂO È DO TIPO OAuth2");
        e.printStackTrace();
      }
      
      // sempre nega o acesso quando nao for GrantType PASSWORD
      return false;
  }
  
  @Override
  protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException ae, ServletRequest request,
                                   ServletResponse response) {
      LOG.debug("onLoginFailure");
      HttpServletResponse httpResponse = WebUtils.toHttp(response);
      httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      return false;
  }
  

}
