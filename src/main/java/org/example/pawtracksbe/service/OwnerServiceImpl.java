package org.example.pawtracksbe.service;

import org.example.pawtracksbe.dto.CreateOwnerRequestDto;
import org.example.pawtracksbe.dto.OwnerResponseDto;
import org.example.pawtracksbe.entity.Owner;
import org.example.pawtracksbe.exception.ResourceNotFoundException;
import org.example.pawtracksbe.mapper.OwnerMapper;
import org.example.pawtracksbe.repository.OwnerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class OwnerServiceImpl implements OwnerService {
    private final OwnerRepository ownerRepository;
    private final OwnerMapper ownerMapper;

    @Autowired
    OwnerServiceImpl(OwnerRepository ownerRepository,
                     OwnerMapper ownerMapper) {
        this.ownerRepository = ownerRepository;
        this.ownerMapper = ownerMapper;
    }

    @Override
    @Transactional(readOnly = true)
    public List<OwnerResponseDto> getAllOwners() {
        List<Owner> owners = ownerRepository.findAll();
        return ownerMapper.ownersToOwnerResponseDtos(owners);
    }

    @Override
    @Transactional
    public OwnerResponseDto createOwner(CreateOwnerRequestDto requestDto) {
        Owner owner = ownerMapper.createOwnerRequestDtoToOwner(requestDto);
        Owner savedOwner = ownerRepository.save(owner);
        return ownerMapper.ownerToOwnerResponseDto(savedOwner);
    }

    @Override
    @Transactional
    public OwnerResponseDto updateOwner(Long id, CreateOwnerRequestDto requestDto) {
        Owner existingOwner = ownerRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Owner not found"));

        ownerMapper.updateOwnerFromDto(requestDto, existingOwner);

        Owner savedOwner = ownerRepository.save(existingOwner);

        return ownerMapper.ownerToOwnerResponseDto(savedOwner);
    }

    @Override
    @Transactional
    public void deleteOwner(Long id) {
        if (!ownerRepository.existsById(id)) {
            throw new ResourceNotFoundException("Owner not found");
        }
        ownerRepository.deleteById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public OwnerResponseDto getOwnerById(Long id) {
        Owner owner = ownerRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Owner not found"));
        return ownerMapper.ownerToOwnerResponseDto(owner);
    }
}
