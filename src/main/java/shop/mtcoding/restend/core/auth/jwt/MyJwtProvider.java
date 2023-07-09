package shop.mtcoding.restend.core.auth.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import shop.mtcoding.restend.core.annotation.MyErrorLog;
import shop.mtcoding.restend.core.annotation.MyLog;
import shop.mtcoding.restend.core.util.RedisUtil;
import shop.mtcoding.restend.model.user.User;

import java.util.Date;

@RequiredArgsConstructor
@Component
public class MyJwtProvider {
    private final RedisUtil redisUtil;
    private static final String SUBJECT = "finalproject";
    private static final Long EXP_ACCESS = 1000 * 60 * 2L; // 1분
    protected static final Long EXP_REFRESH = 1000 * 60 * 4L; // 4분
    public static final String TOKEN_PREFIX = "Bearer "; // 스페이스 필요함
    public static final String HEADER_ACCESS = "Authorization";
    public static final String HEADER_REFRESH = "RefreshToken";
    public static final String SECRET_ACCESS = "5b/ziuLkoHT3aHeL+jFhzSwGEWx/bFvO1vW34z1htkZkzl3kObYOxKot8ceMPiCk3WInzzK6JGMy1TTZJ9Z3DpTgh5Hcyegq8rTgT91BKt5TzQtBG29Is4OSY5NL6vzZ";
    public static final String SECRET_REFRESH = "bridge";

    // Access 토큰 생성
    @MyLog
    @MyErrorLog
    public static String createAccess(User user) {
        String accessToken = TOKEN_PREFIX + JWT.create()
                .withSubject(SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + EXP_ACCESS))
                .withClaim("id", user.getId())
                .withClaim("role", user.getRole())
                .sign(Algorithm.HMAC512(SECRET_ACCESS));
        return accessToken;
    }

    // Refresh 토큰 생성
    @MyLog
    @MyErrorLog
    public String createRefresh(User user) {
        String refreshToken = TOKEN_PREFIX + JWT.create()
                .withSubject(SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + EXP_REFRESH))
                .withClaim("id", user.getId())
                .withClaim("role", user.getRole())
                .sign(Algorithm.HMAC512(SECRET_REFRESH));
        // Redis에 refresh token을 저장
        redisUtil.set(
                user.getId() + user.getRole(),
                refreshToken,
                EXP_REFRESH
        );
        return refreshToken;
    }


    // Access 토큰을 검증
    @MyLog
    @MyErrorLog
    public static DecodedJWT verifyAccess(String jwt) throws SignatureVerificationException, TokenExpiredException {
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(SECRET_ACCESS))
                .build().verify(jwt);
        return decodedJWT;
    }

    // Refresh 토큰을 검증
    @MyLog
    @MyErrorLog
    public static DecodedJWT verifyRefresh(String jwt) throws SignatureVerificationException, TokenExpiredException {
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(SECRET_REFRESH))
                .build().verify(jwt);
        return decodedJWT;
    }
}