package jy.lib.auth.security.jwt.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GenerateJwtRequest {
    private Long userId;
    private String username;

    @Builder
    public GenerateJwtRequest(Long userId, String username) {
        this.userId = userId;
        this.username = username;
    }
}
