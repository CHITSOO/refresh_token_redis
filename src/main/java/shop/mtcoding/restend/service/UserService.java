package shop.mtcoding.restend.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.util.Pair;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import shop.mtcoding.restend.core.annotation.MyErrorLog;
import shop.mtcoding.restend.core.annotation.MyLog;
import shop.mtcoding.restend.core.auth.jwt.MyJwtProvider;
import shop.mtcoding.restend.core.auth.session.MyUserDetails;
import shop.mtcoding.restend.core.exception.Exception400;
import shop.mtcoding.restend.core.exception.Exception404;
import shop.mtcoding.restend.core.exception.Exception500;
import shop.mtcoding.restend.core.util.RedisUtil;
import shop.mtcoding.restend.dto.user.UserRequest;
import shop.mtcoding.restend.dto.user.UserResponse;
import shop.mtcoding.restend.model.user.User;
import shop.mtcoding.restend.model.user.UserRepository;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@Slf4j
@Transactional(readOnly = true)
@RequiredArgsConstructor
@Service
public class UserService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final MyJwtProvider myJwtProvider;
    private final RedisUtil redisUtil;

    @MyLog
    @MyErrorLog
    @Transactional
    public UserResponse.JoinOutDTO 회원가입(UserRequest.JoinInDTO joinInDTO){
        Optional<User> userOP =userRepository.findByUsername(joinInDTO.getUsername());
        if(userOP.isPresent()){
            // 이 부분이 try catch 안에 있으면 Exception500에게 제어권을 뺏긴다.
            throw new Exception400("username", "유저네임이 존재합니다");
        }
        String encPassword = passwordEncoder.encode(joinInDTO.getPassword()); // 60Byte
        joinInDTO.setPassword(encPassword);
        System.out.println("encPassword : "+encPassword);

        // 디비 save 되는 쪽만 try catch로 처리하자.
        try {
            User userPS = userRepository.save(joinInDTO.toEntity());
            return new UserResponse.JoinOutDTO(userPS);
        }catch (Exception e){
            throw new Exception500("회원가입 실패 : "+e.getMessage());
        }
    }

    @MyLog
    @MyErrorLog
    public Pair<String, String> 로그인(UserRequest.LoginInDTO loginInDTO) {
        try {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                    = new UsernamePasswordAuthenticationToken(loginInDTO.getUsername(), loginInDTO.getPassword());
            Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
            MyUserDetails myUserDetails = (MyUserDetails) authentication.getPrincipal();

            //로그인 성공하면 액세스 토큰, 리프레시 토큰 발급.
            String accessjwt = myJwtProvider.createAccess(myUserDetails.getUser());
            String refreshjwt = myJwtProvider.createRefresh(myUserDetails.getUser());
            return Pair.of(accessjwt, refreshjwt);
        }catch (Exception e){
            throw new Exception500("로그인 실패");
        }
    }

    @MyLog
    @MyErrorLog
    @Transactional
    public Pair<String, String> RTR토큰재발급(HttpServletRequest request) {
        // access token에서 나온 사용자 정보로 redis에서 refresh token을 조회
        String prefixJwt = request.getHeader(MyJwtProvider.HEADER_ACCESS);
        String jwt = prefixJwt.replace(MyJwtProvider.TOKEN_PREFIX, "");

//        DecodedJWT decodedJWT = null;
//        try {
//            decodedJWT = MyJwtProvider.verifyRefresh(jwt);
//        } catch (SignatureVerificationException sve) {
//            log.error("액세스 토큰 검증 실패");
//        }
        DecodedJWT decodedJWT = JWT.decode(jwt);

        Long id = decodedJWT.getClaim("id").asLong();
        String role = decodedJWT.getClaim("role").asString();
        String key = id + role;
        System.out.println(key);
        String refreshToken = redisUtil.get(key);
        System.out.println(refreshToken);
        if (refreshToken == null) {
            log.error("레디스에서 찾을 수 없는 리프레시 토큰입니다. [key: {}]", key);
            throw new Exception500("레디스에서 찾을 수 없는 리프레시 토큰입니다.");
        }

        jwt = request.getHeader(MyJwtProvider.HEADER_REFRESH);
        System.out.println(jwt);
        // 이 refresh token이 사용자가 요청한 refresh token과 같다면
        if(!jwt.equals(refreshToken)){
            throw new Exception500("레디스에 저장된 리프레시 토큰과 요청한 리프레시 토큰이 다릅니다.");
        }

        // 기존의 refresh token 삭제 후 새로 refresh token과 access token을 생성해서 응답
        redisUtil.delete(key);
        log.info("레디스에서 리프레시 토큰을 삭제했습니다. [key: {}]", key);

        //액세스 토큰, 리프레시 토큰 발급.
        try {
            User userPS = userRepository.findById(id)
                    .orElseThrow(() -> new Exception500("해당하는 사용자가 없습니다."));
            String accessjwt = myJwtProvider.createAccess(userPS);
            String refreshjwt = myJwtProvider.createRefresh(userPS);
            return Pair.of(accessjwt, refreshjwt);
        } catch (Exception e){
            throw new Exception500("토큰 재발급 실패");
        }

    }

    @MyLog
    @MyErrorLog
    @Transactional
    public void 로그아웃(HttpServletRequest request) {
        // Redis에서 해당 유저의 refresh token 삭제
        String prefixJwt = request.getHeader(MyJwtProvider.HEADER_REFRESH);
        String jwt = prefixJwt.replace(MyJwtProvider.TOKEN_PREFIX, "");

        DecodedJWT decodedJWT = null;
        try {
            decodedJWT = MyJwtProvider.verifyRefresh(jwt);
        } catch (SignatureVerificationException sve) {
            log.error("리프레시 토큰 검증 실패");
        }

        Long id = decodedJWT.getClaim("id").asLong();
        String role = decodedJWT.getClaim("role").asString();
        String key = id + role;
        if (redisUtil.get(key) == null) {
            log.error("레디스에서 찾을 수 없는 리프레시 토큰입니다. [key: {}]", key);
            throw new Exception500("레디스에서 찾을 수 없는 리프레시 토큰입니다.");
        }

        redisUtil.delete(key);
        log.info("레디스에서 리프레시 토큰을 삭제했습니다. [key: {}]", key);


        // 해당 access token을 Redis의 블랙리스트로 추가
        String accessToken = request.getHeader(MyJwtProvider.HEADER_ACCESS);
        jwt = accessToken.replace(MyJwtProvider.TOKEN_PREFIX, "");
        try {
            decodedJWT = MyJwtProvider.verifyAccess(jwt);
        } catch (SignatureVerificationException sve) {
            log.error("액세스 토큰 검증 실패");
        }
        System.out.println(jwt);
        Long remainingTimeMillis = decodedJWT.getExpiresAt().getTime() - System.currentTimeMillis();
        redisUtil.setBlackList(jwt, "access_token", remainingTimeMillis);
    }


    @MyLog
    @MyErrorLog
    @Transactional
    public UserResponse.DetailOutDTO 회원상세보기(Long id) {
        User userPS = userRepository.findById(id).orElseThrow(
                ()-> new Exception404("해당 유저를 찾을 수 없습니다")
        );
        return new UserResponse.DetailOutDTO(userPS);
    }
}
