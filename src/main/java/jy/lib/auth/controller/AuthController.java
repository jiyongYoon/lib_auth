package jy.lib.auth.controller;

import jy.lib.auth.dto.UserDto;
import jy.lib.auth.security.jwt.RefreshTokenStorage;
import jy.lib.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthController {

    private final UserService userService;
    private final RefreshTokenStorage refreshTokenStorage;

    @PostMapping("/signup")
    public UserDto createUser(@RequestBody UserDto userDto) {
        return userService.createUser(userDto);
    }

    @GetMapping("/token")
    public Map<String, String> getSavedToken() {
        return refreshTokenStorage.getInstance();
    }
}
