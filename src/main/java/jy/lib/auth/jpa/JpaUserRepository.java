package jy.lib.auth.jpa;

import jy.lib.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaUserRepository extends JpaRepository<User, Long> {

    Optional<User> findUserByUserEmail(String userEmail);
}
