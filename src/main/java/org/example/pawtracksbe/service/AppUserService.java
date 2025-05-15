package org.example.pawtracksbe.service;

import org.example.pawtracksbe.dto.CreateUserRequestDto;
import org.example.pawtracksbe.dto.UserResponseDto;
import org.example.pawtracksbe.entity.AppUser;

import java.util.Optional;

public interface AppUserService {
    UserResponseDto createUser(CreateUserRequestDto createUserRequestDto);
    Optional<UserResponseDto> getUserById(Long id);
    Optional<UserResponseDto> getUserByUsername(String username);
    AppUser loadAppUserByUsername(String username);
}
