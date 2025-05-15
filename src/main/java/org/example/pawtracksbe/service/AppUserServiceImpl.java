package org.example.pawtracksbe.service;

import org.example.pawtracksbe.dto.CreateUserRequestDto;
import org.example.pawtracksbe.dto.UserResponseDto;
import org.example.pawtracksbe.entity.AppUser;
import org.example.pawtracksbe.mapper.UserMapper;
import org.example.pawtracksbe.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
public class AppUserServiceImpl implements AppUserService {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    private static final String DEFAULT_ROLE = "ROLE_USER";

    @Autowired
    public AppUserServiceImpl(AppUserRepository appUserRepository,
                              PasswordEncoder passwordEncoder,
                              UserMapper userMapper) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
    }

    @Override
    @Transactional
    public UserResponseDto createUser(CreateUserRequestDto createUserRequestDto) {
        if (appUserRepository.findByUsername(createUserRequestDto.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }

        AppUser appUser = userMapper.createUserRequestDtoToAppUser(createUserRequestDto);
        appUser.setPassword(passwordEncoder.encode(createUserRequestDto.getPassword()));

        appUser.setRoles(Collections.singletonList(DEFAULT_ROLE));

        AppUser savedUser = appUserRepository.save(appUser);
        return userMapper.appUserToUserResponseDto(savedUser);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserResponseDto> getUserById(Long id) {
        return appUserRepository.findById(id)
                .map(userMapper::appUserToUserResponseDto);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserResponseDto> getUserByUsername(String username) {
        return appUserRepository.findByUsername(username)
                .map(userMapper::appUserToUserResponseDto);
    }

    @Override
    @Transactional(readOnly = true)
    public AppUser loadAppUserByUsername(String username) {
        return appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("AppUser not found with username: " + username));
    }
}
