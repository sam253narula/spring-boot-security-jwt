package com.example.springsecurityjwt.serviceimpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.stereotype.Service;

import com.example.springsecurityjwt.entity.MyUser;
import com.example.springsecurityjwt.repository.UserRepository;

import java.util.Collections;

@Service
public class MyUserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		MyUser myUser = MyUser.builder().name(username).build();
		ExampleMatcher exampleMatcher = ExampleMatcher.matching()
				.withMatcher("name", ExampleMatcher.GenericPropertyMatchers.contains())
				.withIgnorePaths("id", "password");
		Example<MyUser> example = Example.of(myUser, exampleMatcher);
		MyUser myUser2 = userRepository.findOne(example).get();
		return new User(myUser2.getName(), myUser2.getPassword(), Collections.emptyList());
	}
}
