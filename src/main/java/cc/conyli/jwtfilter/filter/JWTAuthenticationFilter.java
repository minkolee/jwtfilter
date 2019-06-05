package cc.conyli.jwtfilter.filter;

import cc.conyli.jwtfilter.jwt.JWTUtils;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private Logger logger = LoggerFactory.getLogger(getClass());

    // 第一步，创建域，这里无法使用Spring框架的@Autowired自动注入，因为过滤器的请求还没有到框架里边，也就没有进到IOC容器
    private AuthenticationManager authenticationManager;
    // 依然是第一步，创建构造器
    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        //这条代码是这个种类的过滤器特有的，限制了这个过滤器监听的URL。当然，这个逻辑也可以自行编写或者进行具体配置。
        //这里就将其限定为"/api/auth"
        setFilterProcessesUrl(JWTUtils.AUTH_LOGIN_URL);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //抽象类提供了两个方法用户获取用户名和密码，其实内部就是request.getParameter方法
        String username = this.obtainUsername(request);
        String password = this.obtainPassword(request);
//        logger.info("尝试认证");
        //和原来方法的逻辑一样，创建UsernamePasswordAuthenticationToken对象
        //注意这里是两参数构造器，构造器其中是this.setAuthenticated(false)，说明该身份未通过认证
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        this.setDetails(request, authenticationToken);
        //和原来方法的逻辑一样，但是必须要换成自己的域，而不是原来方法的this.getAuthenticationManager().authenticate(authRequest)语句
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        //从Authentication对象中取出User信息
        User user = ((User) authResult.getPrincipal());

//        logger.info("成功认证后的Authentication对象是：" + authResult.toString());

        //将权限列表转换为一个数组列表，方便转换成JSON
        //user.getAuthorities()返回的是user对象中的Collection<GrantedAuthority>，authority.getAuthority()则返回权限字符串名称，最后得到一个字符串列表
        List<String> roles = user.getAuthorities().stream().map(authority -> authority.getAuthority()).collect(Collectors.toList());
        //把用户名，TOKEN发行者，过期日期，权限列表字符串写入到claims中，然后使用唯一的Key进行签名，最后生成JWT字符串
        String JWTTOken = Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuer(JWTUtils.TOKEN_ISSUER)
                .setExpiration(new Date(System.currentTimeMillis() + 3600*1000))
                .claim("role", roles)
                .signWith(JWTUtils.getKey())
                .compact();
//        logger.info("生成的JWT是：|| " + JWTTOken + " ||");
        //故意设置一个特殊的状态码看看
        response.setStatus(255);
        //响应头设置上Authorization信息
        response.setHeader(JWTUtils.TOKEN_HEADER, JWTTOken);

        //在原始的代码中，这里还去调用了成功之后的handler，从而继续向下验证或者跳转到刚才登录成功的URL。
        //由于我们的目的是返回token，这里不调用任何东西。则最终不会调用filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
