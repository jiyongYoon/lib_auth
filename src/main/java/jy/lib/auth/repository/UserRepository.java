package jy.lib.auth.repository;

import jy.lib.auth.entity.User;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository {

    List<User> findAll();

    Optional<User> findById(Long userId);

    Optional<User> findByEmail(String userEmail);

    User save(User user);

    void delete(Long userId);
}
