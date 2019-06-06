package cc.conyli.jwtfilter.filter;

import cc.conyli.jwtfilter.jwt.JWTUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 这个过滤器可以配置在Spring Security中，也可以配置在Spring普通的@webFilter中，如果这么配置这个过滤器的顺序是在Spring Security之后的
 * 此时就仅仅针对/api/vote来进行保护了。
 * 此时由于逻辑，所以对于其他路径的访问，都需要认证，但是过滤器里根本就没有配置认证，所以一律是403 Forbidden
 *
 * 看来还是写在Spring Security里统一管理比较好，仅保留开放的端口，其他都封堵上
 *
 */

//@WebFilter(urlPatterns = "/api/vote")
public class JWTTokenFilter extends OncePerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(getClass());


    //重写实际进行过滤操作的doFilterInternal抽象方法
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        logger.info("过滤器2执行了");

        //获取URL
        String targetPath = httpServletRequest.getRequestURI();
        //如果访问的是根路径，直接放行
        if (targetPath.equals("/")) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }

        //尝试获取TOKEN
        String JWTToken = httpServletRequest.getHeader("Authorization");
        //如果TOKEN不为空，尝试解析JWTToken并且组装Authentication实现对象即UsernamePasswordAuthenticationToken
        if (JWTToken != null) {
            Authentication authentication = null;
            //尝试解析的过程中如果出错，就设置一个特殊的响应码，然后直接返回，不再执行后续操作
            try {
                authentication = getAuthenticationFromToken(JWTToken);
            } catch (Exception ex) {
                logger.info(ex.toString());
                httpServletResponse.setStatus(403);
                return;
            }
            //如果成功拿到UsernamePasswordAuthenticationToken，设置到安全上下文上，然后放行
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(httpServletRequest, httpServletResponse);

        } else {
            //如果TOKEN不存在，直接返回401错误，表示未认证
            httpServletResponse.setStatus(401);
        }

    }

    private Authentication getAuthenticationFromToken(String token) throws Exception {
        //尝试验证JWT
        //解析第一部，获取解析后的前两部分的拼合对象
        Jws<Claims> jws = Jwts.parser().setSigningKey(JWTUtils.getKey()).parseClaimsJws(token);
        //从claims中获取放入的用户名
        String username = jws.getBody().getSubject();
        //从role字符串数组转换成权限对象
        ArrayList<String> roleStrings = (ArrayList<String>)jws.getBody().get("role");
        List<GrantedAuthority> authorities = roleStrings.stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
        //组装UsernamePasswordAuthenticationToken并返回这个认证对象，是三参数构造器，说明认证通过
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
        return authenticationToken;
        }
}