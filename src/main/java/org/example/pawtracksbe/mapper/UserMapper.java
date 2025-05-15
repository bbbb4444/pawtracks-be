package org.example.pawtracksbe.mapper;

import org.example.pawtracksbe.dto.CreateUserRequestDto;
import org.example.pawtracksbe.dto.UserResponseDto;
import org.example.pawtracksbe.entity.AppUser;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(target = "id", ignore = true)
    AppUser createUserRequestDtoToAppUser(CreateUserRequestDto createUserRequestDto);

    UserResponseDto appUserToUserResponseDto(AppUser appUser);
}
