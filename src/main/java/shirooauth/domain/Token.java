package shirooauth.domain;

import org.apache.shiro.authc.AuthenticationToken;

public class Token implements AuthenticationToken {
  
  private String authCode;
  private String principal;
  
  public String getAuthCode() {
    return authCode;
  }
  public void setAuthCode(String authCode) {
    this.authCode = authCode;
  }
  public String getPrincipal() {
    return principal;
  }
  public void setPrincipal(String principal) {
    this.principal = principal;
  }

  @Override
  public Object getCredentials() {
    return getAuthCode();
  }
}
