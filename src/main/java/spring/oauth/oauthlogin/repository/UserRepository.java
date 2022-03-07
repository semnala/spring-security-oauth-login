package spring.oauth.oauthlogin.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.oauth.oauthlogin.model.User;

// CRUD 함수를 JpaRepository가 들고 있음
// @Repository 어노테이션이 없어도 IoC가 된다. JpaRepository를 상속했으므로
public interface UserRepository extends JpaRepository<User, Integer> {

    public User findByUsername(String username);
}
