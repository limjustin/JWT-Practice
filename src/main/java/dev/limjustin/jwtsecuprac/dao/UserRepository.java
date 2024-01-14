package dev.limjustin.jwtsecuprac.dao;

import dev.limjustin.jwtsecuprac.model.UserDAO;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserDAO, Long> {
    UserDAO findByUsername(String username);
}
