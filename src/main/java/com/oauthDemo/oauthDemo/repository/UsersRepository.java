package com.oauthDemo.oauthDemo.repository;

import com.oauthDemo.oauthDemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsersRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
}
