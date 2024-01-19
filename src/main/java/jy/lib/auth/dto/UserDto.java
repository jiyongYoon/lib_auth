package jy.lib.auth.dto;

import jy.lib.auth.entity.User;
import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class UserDto {

    private Long userId;
    private String userEmail;
    private String userPassword;
    private String userRole;

    public static UserDto toDto(User user) {
        return UserDto.builder()
                .userId(user.getUserId())
                .userEmail(user.getUserEmail())
                .userPassword(user.getUserPassword())
                .userRole(user.getUserRole())
                .build();
    }
}
