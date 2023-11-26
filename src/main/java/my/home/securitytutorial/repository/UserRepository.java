package my.home.securitytutorial.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import my.home.securitytutorial.domain.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);
}
