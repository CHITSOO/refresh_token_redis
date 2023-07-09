# Refresh Token + Redis + RTR + BlakList + JWT

## 1. 리프레시 토큰 관련 기술 및 구현
- JWT로 액세스 토큰 발급
- JWT로 리프레시 토큰 발급
- 리프레시 토큰은 레디스에 저장하여 만료시간이 지나면 자동 삭제
- 레디스에 저장시 키값은 ID값으로 함
- 401 응답시 리프레시 토큰으로 액세스 토큰 재발급 -> 이 레포지토리에서는 액세스 토큰으로 키값 구함
- 리프레시 토큰으로 액세스 토큰 재발급시, 이 레포지토리에서는 액세스 토큰을 받아서 레디스의 키값 찾음
- 로그아웃시 액세스 토큰을 레디스에 블랙리스트로 저장하여 해당 액세스 토큰으로 로그인 못하게 막음

## 2. boiler plate 기술
- Springboot 2.7
- H2, JPA
- Security Stateless 설정
- JWT 설정
- AOP 설정
  - DebugLog
  - ErrorLog
  - Validation
  - Exception
- CORS 설정
- WebMvcConfigure 설정 (Resource Handler)
- Junit 통합테스트 및 RestDoc 문서 자동화
- Junit 단위테스트 

## 3. 스프링부트 배포

### 3.1 gradle 빌드하기
./gradlew clean build

### 3.2 prod로 실행
java -Dspring.profiles.active=prod -jar restend-0.0.1-SNAPSHOT.jar
리눅스에서는 아래와 같이 *로 실행이 가능하다.
java -Dspring.profiles.active=prod -jar *.jar
