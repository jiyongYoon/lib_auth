package jy.lib.auth.entity;

import jy.lib.auth.security.oauth.Provider;
import lombok.*;

import javax.persistence.*;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
@Table(name = "tb_user",
        uniqueConstraints = {
        @UniqueConstraint(columnNames = { "userEmail" })
})
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    private String userEmail;

    private String userPassword;

    private String userRole;

    @Enumerated(EnumType.STRING)
    private Provider provider;

}
