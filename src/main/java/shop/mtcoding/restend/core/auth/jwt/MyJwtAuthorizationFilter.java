package shop.mtcoding.restend.core.auth.jwt;

import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import shop.mtcoding.restend.core.auth.session.MyUserDetails;
import shop.mtcoding.restend.core.exception.Exception400;
import shop.mtcoding.restend.core.exception.Exception401;
import shop.mtcoding.restend.core.exception.Exception403;
import shop.mtcoding.restend.core.exception.Exception500;
import shop.mtcoding.restend.core.util.MyFilterResponseUtil;
import shop.mtcoding.restend.core.util.RedisUtil;
import shop.mtcoding.restend.model.user.User;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class MyJwtAuthorizationFilter extends BasicAuthenticationFilter {
    private final RedisUtil redisUtil;

    public MyJwtAuthorizationFilter(RedisUtil redisUtil, AuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.redisUtil = redisUtil;
    }

    // SecurityConfig 에 인증을 설정한 API에 대한 request 요청은 모두 이 필터를 거치기 때문에 토큰 정보가 없거나 유효하지 않은 경우 정상적으로 수행되지 않음
    // 헤더(Authorization)에 있는 토큰을 꺼내 이상이 없는 경우 SecurityContext에 저장
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String prefixJwt = request.getHeader(MyJwtProvider.HEADER_ACCESS);

        if (prefixJwt == null) {
            chain.doFilter(request, response);
            return;
        }

        String jwt = prefixJwt.replace(MyJwtProvider.TOKEN_PREFIX, "");
        try {
            System.out.println("디버그 : 토큰 있음");
            DecodedJWT decodedJWT = MyJwtProvider.verifyAccess(jwt);
            // access token이 Blacklist에 등록되었는지 Redis를 조회하여 확인
            if(redisUtil.hasKeyBlackList(jwt)) {
                // 블랙리스트에 저장된 토큰이라면 에러를 반환
                log.error("블랙리스트에 등록된 액세스 토큰");
                MyFilterResponseUtil.serverError(response, new Exception500("블랙리스트에 등록된 액세스 토큰"));
            }
            Long id = decodedJWT.getClaim("id").asLong();
            String role = decodedJWT.getClaim("role").asString();

            User user = User.builder().id(id).role(role).build();
            MyUserDetails myUserDetails = new MyUserDetails(user);
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            myUserDetails,
                            myUserDetails.getPassword(),
                            myUserDetails.getAuthorities()
                    );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("디버그 : 인증 객체 만들어짐");
        } catch (RedisConnectionFailureException e) {
            SecurityContextHolder.clearContext();
            log.error("Redis 연결 실패");
        }catch (SignatureVerificationException sve) {
            log.error("액세스 토큰 검증 실패");
        } catch (TokenExpiredException tee) {
            log.error("액세스 토큰 만료됨");
        } finally {
            chain.doFilter(request, response);
        }
    }
}