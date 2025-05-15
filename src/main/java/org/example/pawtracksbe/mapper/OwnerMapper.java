package org.example.pawtracksbe.mapper;

import org.example.pawtracksbe.dto.CreateOwnerRequestDto;
import org.example.pawtracksbe.dto.OwnerResponseDto;
import org.example.pawtracksbe.entity.Owner;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import org.mapstruct.NullValuePropertyMappingStrategy;

import java.util.List;

@Mapper(componentModel = "spring",
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
public interface OwnerMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "pets", source = "pets")
    Owner createOwnerRequestDtoToOwner(CreateOwnerRequestDto dto);

    OwnerResponseDto ownerToOwnerResponseDto(Owner owner);
    List<OwnerResponseDto> ownersToOwnerResponseDtos(List<Owner> owners);

    @Mapping(target = "id", ignore = true)
    void updateOwnerFromDto(CreateOwnerRequestDto dto, @MappingTarget Owner owner);

}