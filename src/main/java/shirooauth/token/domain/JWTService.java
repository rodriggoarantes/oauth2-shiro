package shirooauth.token.domain;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service("JWTService")
public class JWTService {
  
  private static final Logger LOG = LoggerFactory.getLogger(JWTService.class);
  
  public static final Map<String, String> repository = new HashMap<>(0);
  
  private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
  
  
  @Deprecated
  public final Key getSignatureKeyJWTS() {
    Key signingKey = new SecretKeySpec(("PCSISTEMAS").getBytes(), signatureAlgorithm.getValue());
    return signingKey;
  }
  
  @Deprecated
  public String createTokenAccessJWTS(String clientID) {
    
    long nowMillis = System.currentTimeMillis();
    Date now = new Date(nowMillis);
    Date expiration = new Date(nowMillis + 3600000);
    
    String token = "";
    
    Map<String, Object> claims = new HashMap<>();
    claims.put("origin", "jwtbuilder");
    
    //Let's set the JWT Claims
    JwtBuilder builder = Jwts.builder()
                                .setId(clientID)
                                .setIssuedAt(now)
                                .setSubject("RODRIGO")
                                .setIssuer("winthoranywhere")
                                .signWith(signatureAlgorithm, getSignatureKeyJWTS())
                                .setExpiration(expiration)
                                .setClaims(claims)
                                ;
    
    //Builds the JWT and serializes it to a compact, URL-safe string
    token = builder.compact();
    LOG.debug("TOKEN:1: {}", token);
    return token;
  }
  
  
  private final Algorithm getSignatureKey() {
    try {
      return Algorithm.HMAC256("PCSISTEMAS");
    } catch (IllegalArgumentException | UnsupportedEncodingException e) {
      LOG.error("Erro ao gerar chave secreta", e);
    }
    return null;
  }

  public String createTokenAccess(String clientID) {
 
    long nowMillis = System.currentTimeMillis();
    Date now = new Date(nowMillis);
    Date expiration = new Date(nowMillis + 3600000);
    
    String token = JWT.create()
        .withIssuer("winthoranywhere")
        .withSubject("RODRIGO")
        .withExpiresAt(expiration)
        .withJWTId(clientID)
        .withIssuedAt(now)
        .withClaim("origin", "auth0") // custom claims
        .sign(getSignatureKey());
    
    LOG.debug("TOKEN:2: {}", token);
    
    return token;
  }
  
  
  public boolean isValidToken(final String jwtToken) {
    try {
      final Algorithm algorithmHS = Algorithm.HMAC256("PCSISTEMAS");
      
      final JWTVerifier verifier = JWT.require(algorithmHS).build();
      
      // verify valid token
      final DecodedJWT jwt = verifier.verify(jwtToken);
      final Claim authParam = jwt.getClaim("origin");
      
      LOG.debug("jwt:TOKEN:A = {}", jwt.getId());
      LOG.debug("jwt:TOKEN:B = {}", authParam.asString());
      
      return jwt.getId().equals("pcsistemas") 
          && !authParam.isNull()
            && authParam.asString().equals("auth0");
      
    } catch (Exception e) {
      LOG.error("isValidToken: {}", e.getMessage());
    }
    return false;
  }
  
}
