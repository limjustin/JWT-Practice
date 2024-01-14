package dev.limjustin.jwtsecuprac.config;

import dev.limjustin.jwtsecuprac.service.JwtUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private final JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    private final JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        // 사용자의 요청이 들어오면 이 필터를 거치게 된다!
        // 당연히 컨트롤러 안에 있는 핸들러 메서드보다 먼저 찍히지! 필터가 먼저니까!
        // 결론 : 어쨌든 필터는 컨트롤러에서 요청을 처리하기 전에 통과하는 곳!
        System.out.println("JwtRequestFilter.doFilterInternal");

        String requestTokenHeader = request.getHeader("Authorization");

        String username = null;
        String jwtToken = null;
        // JWT Token is in the form "Bearer token". Remove Bearer word and get
        // only the Token
        // 요청에 토큰이 있는지 검사 (Check if request has token)
        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
            System.out.println("jwtToken = " + jwtToken);
            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                System.out.println("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {
                System.out.println("JWT Token has expired");
            }
        } else {
            logger.warn("JWT Token does not begin with Bearer String");
        }  // 필터 통과하면? 어~ 그냥 가던 길 가~ 알맞은 컨트롤러 메서드에 연결해줄게~

        System.out.println("Before validate = " + SecurityContextHolder.getContext().getAuthentication());
        // 다시 요청하면 여기서 null 값 나오는게 이해되지 않음

        // Once we get the token validate it.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            System.out.println("JwtRequestFilter.doFilterInternal.validate");
            UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);

            // if token is valid configure Spring Security to manually set
            // authentication
            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {  // 토큰이 인증 완료되었을 경우

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());  // UsernamePasswordAuthenticationToken 객체 생성
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // After setting the Authentication in the context, we specify
                // that the current user is authenticated. So it passes the
                // Spring Security Configurations successfully.
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);  // SecurityContextHolder 통해 저장
            }
        }
        System.out.println("After validate = " + SecurityContextHolder.getContext().getAuthentication());
        chain.doFilter(request, response);
    }

}
