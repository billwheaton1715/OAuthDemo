package com.siftit.domain.oauth2demo.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

@Getter
@Setter
@Entity
@Table(name = "authorities")
public class Authority implements GrantedAuthority {
    @EmbeddedId
    private AuthorityId id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "username", nullable = false, insertable = false, updatable = false)
    private User user;

    @Override
    public String getAuthority() {
        return id.getAuthority();
    }
}
