package shop.mtcoding.restend.model.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    @Query("select u from User u where u.username = :username")
    Optional<User> findByUsername(@Param("username") String username);

    // 유저가 이메일과 패스워드를 올바르게 입력했는지 판단하기 위한 메소드
    Optional<User> findByEmailAndPassword(final String email, final String password);
}