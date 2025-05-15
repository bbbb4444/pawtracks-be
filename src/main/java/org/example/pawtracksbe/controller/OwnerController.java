package org.example.pawtracksbe.controller;

import jakarta.validation.Valid;
import org.example.pawtracksbe.dto.CreateOwnerRequestDto;
import org.example.pawtracksbe.dto.OwnerResponseDto;
import org.example.pawtracksbe.service.OwnerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/owners")
public class OwnerController {

    private final OwnerService ownerService;

    @Autowired
    public OwnerController(OwnerService ownerService) {
        this.ownerService = ownerService;
    }

    @GetMapping
    public ResponseEntity<List<OwnerResponseDto>> getAllOwners() {
        List<OwnerResponseDto> owners = ownerService.getAllOwners();
        return ResponseEntity.ok(owners);
    }

    @PostMapping
    public ResponseEntity<OwnerResponseDto> createOwner(@Valid @RequestBody CreateOwnerRequestDto createOwnerRequestDto) {
        OwnerResponseDto createdOwner = ownerService.createOwner(createOwnerRequestDto);
        return new ResponseEntity<>(createdOwner, HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    public ResponseEntity<OwnerResponseDto> updateOwner(@PathVariable Long id,
                                                        @Valid @RequestBody CreateOwnerRequestDto updateOwnerRequestDto) {
        OwnerResponseDto updatedOwner = ownerService.updateOwner(id, updateOwnerRequestDto);
        return ResponseEntity.ok(updatedOwner);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<OwnerResponseDto> deleteOwner(@PathVariable Long id) {
        ownerService.deleteOwner(id);
        return ResponseEntity.noContent().build();
    }
}
