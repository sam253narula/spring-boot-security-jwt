package com.example.springsecurityjwt.repository;

import org.springframework.data.domain.Example;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.springsecurityjwt.entity.MyUser;

@Repository
public interface UserRepository extends JpaRepository<MyUser,Integer> {

    
}
