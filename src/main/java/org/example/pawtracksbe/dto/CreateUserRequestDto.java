package org.example.pawtracksbe.dto;

import lombok.Data;

@Data
public class CreateUserRequestDto
{
    private String username;
    private String password;
}
