package org.example.pawtracksbe.service;

import org.example.pawtracksbe.dto.CreateOwnerRequestDto;
import org.example.pawtracksbe.dto.OwnerResponseDto;

import java.util.List;

public interface OwnerService {
    List<OwnerResponseDto> getAllOwners();
    OwnerResponseDto createOwner(CreateOwnerRequestDto requestDto);
    OwnerResponseDto updateOwner(Long id, CreateOwnerRequestDto requestDto);
    void deleteOwner(Long id);
    OwnerResponseDto getOwnerById(Long id);
}
