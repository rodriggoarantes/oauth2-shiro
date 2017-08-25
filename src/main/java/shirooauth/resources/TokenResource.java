package shirooauth.resources;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class TokenResource {
  
  private static final Logger LOG = LoggerFactory.getLogger(TokenResource.class);
  
  @RequestMapping(value="/token", method = RequestMethod.POST)
  public @ResponseBody String getToken(HttpServletRequest req) {
      LOG.debug("getToken");
      
      try {
        
        OAuthTokenRequest oauthRequest = new OAuthTokenRequest(req);
        String senha = oauthRequest.getPassword();
        String login = oauthRequest.getUsername();
        
        LOG.debug("Login: {} - Senha: {}", login, senha);
        
        OAuthASResponse.OAuthAuthorizationResponseBuilder builder = OAuthASResponse
            .authorizationResponse(req, HttpServletResponse.SC_FOUND);

        // gerar access token
        OAuthIssuerImpl oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());
        builder.setCode(oauthIssuerImpl.authorizationCode());
        builder.setAccessToken(oauthIssuerImpl.accessToken());
        builder.setExpiresIn(3600L);
        builder.setParam("nome", "Rodrigo");
        builder.setParam("login", "rodrigo.arantes");
        
        final OAuthResponse response = builder.buildJSONMessage();
        
        //final Token t = new Token("X", "24/08", "R");
        return response.getBody();
        
      } catch (OAuthSystemException e) {
        e.printStackTrace();
      } catch (OAuthProblemException e) {
        e.printStackTrace();
      }
    
      return null;
  }
  
  @RequiresAuthentication
  @RequestMapping(value="/consulta", method = RequestMethod.GET)
  public String consulta() {
    return "CONSULTA REALIZADA!!!";
  }
  
  @RequiresAuthentication
  @RequestMapping(value="/login", method = RequestMethod.GET)
  public String login() {
    return "LOGIN";
  }
}
