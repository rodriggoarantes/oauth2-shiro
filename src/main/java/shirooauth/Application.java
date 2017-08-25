package shirooauth;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.filter.DelegatingFilterProxy;

import shirooauth.shiro.OAuth2AuthenticationFilter;
import shirooauth.shiro.TokenSessionManager;
import shirooauth.shiro.TokenShiroAuthRealm;

@SpringBootApplication
public class Application {
  
    private static final Logger LOG = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(ApplicationContext ctx) {
        return args -> {
            System.out.println("---");
            String[] beanNames = ctx.getBeanDefinitionNames();
            Arrays.sort(beanNames);
            for (String beanName : beanNames) {
                System.out.println(beanName);
            }
        };
    }
    
    //  custom realm
    @Bean
    @DependsOn("lifecycleBeanPostProcessor")
    public Realm realm() {
        return new TokenShiroAuthRealm();
    }
    
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    @DependsOn("realm")
    public Authenticator authenticator() {
      return (Authenticator) realm();
    }
    
    @Bean
    @DependsOn("realm")
    public Authorizer authorizer() {
      return (Authorizer) realm();
    }
    
    @Bean
    public SessionManager sessionManager() {
      return new TokenSessionManager();
    }
    
    @Bean
    public CacheManager cacheManager() {
        //return new MemoryConstrainedCacheManager();
      
      final EhCacheManager ehCacheManager = new EhCacheManager();
      ehCacheManager.setCacheManagerConfigFile("classpath:ehcache.xml");
      ehCacheManager.setCacheManager(net.sf.ehcache.CacheManager.create());
      return ehCacheManager;
    }
    
    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        chainDefinition.addPathDefinition("/**", "oauth2Authc");
        //chainDefinition.addPathDefinition("/**", "authcBasic[permissive]");
        return chainDefinition;
    }
    
    @Bean(name = "securityManager")
    @DependsOn({"realm", "authenticator", "sessionManager"})
    public DefaultWebSecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm());
        securityManager.setSessionManager(sessionManager());
        securityManager.setCacheManager(cacheManager());
        return securityManager;
    }
    
    @Bean
    @DependsOn("securityManager")
    public ShiroFilterFactoryBean shiroFilterFactoryBean() {
      ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
      shiroFilterFactoryBean.setSecurityManager(securityManager());
      shiroFilterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition().getFilterChainMap());
      
      final Map<String, Filter> filters = new HashMap<>();
      filters.put("oauth2Authc", new OAuth2AuthenticationFilter());
      
      shiroFilterFactoryBean.setFilters( filters );
      return shiroFilterFactoryBean;
    }
    
    @Bean
    public FilterRegistrationBean shiroFilter() {
      DelegatingFilterProxy delegatingFilterProxy = new DelegatingFilterProxy();
      delegatingFilterProxy.setTargetBeanName("shiroFilterFactoryBean");
      delegatingFilterProxy.setTargetFilterLifecycle(true);

      FilterRegistrationBean registrationBean = new FilterRegistrationBean();
      registrationBean.setFilter(delegatingFilterProxy);
      registrationBean.setUrlPatterns(Arrays.asList("/*"));
      registrationBean.setOrder(1);
      
      return registrationBean;
    }
    
    
    
    // ---------- exceptions ------------------
    
    @ExceptionHandler(UnauthenticatedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public void handleException(UnauthenticatedException e) {
        LOG.debug("--> {} was thrown", e.getClass(), e);
    }

    @ExceptionHandler(AuthorizationException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public void handleException(AuthorizationException e) {
      LOG.debug("--> {} was thrown", e.getClass(), e);
    }

}