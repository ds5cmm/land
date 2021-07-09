package io.jarvis.land.repository;


import io.jarvis.land.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {

    public User findByUsername(String username);

}
