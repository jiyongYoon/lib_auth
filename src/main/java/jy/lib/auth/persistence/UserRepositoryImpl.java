package jy.lib.auth.persistence;


import jy.lib.auth.entity.User;
import jy.lib.auth.jpa.JpaUserRepository;
import jy.lib.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class UserRepositoryImpl implements UserRepository {

    private final JpaUserRepository jpaRepository;

    @Override
    public List<User> findAll() {
        return jpaRepository.findAll();
    }

    @Override
    public Optional<User> findById(Long userId) {
        return jpaRepository.findById(userId);
    }

    @Override
    public Optional<User> findByEmail(String userEmail) {
        return jpaRepository.findUserByUserEmail(userEmail);
    }

    @Override
    public User save(User user) {
        return jpaRepository.save(user);
    }

    @Override
    public void delete(Long userId) {
        jpaRepository.deleteById(userId);
    }
}
