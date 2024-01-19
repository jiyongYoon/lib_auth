package jy.lib.auth.service;

import jy.lib.auth.dto.UserDto;
import jy.lib.auth.entity.User;
import jy.lib.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public UserDto createUser(UserDto userDto) {
        User user = User.builder()
                .userEmail(userDto.getUserEmail())
                .userPassword(passwordEncoder.encode(userDto.getUserPassword()))
                .userRole("ROLE_USER")
                .build();

        return UserDto.toDto(userRepository.save(user));
    }
}
