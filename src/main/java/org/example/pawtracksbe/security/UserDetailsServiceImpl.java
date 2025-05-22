package org.example.pawtracksbe.security;

import org.example.pawtracksbe.entity.AppUser;
import org.example.pawtracksbe.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final AppUserRepository appUserRepository;

    @Autowired
    public UserDetailsServiceImpl(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    /**
     * Locates the user based on the username. In the actual implementation, the search
     * may possibly be case sensitive, or case insensitive depending on how the
     * implementation instance is configured. In this case, the database query is
     * case sensitive by default.
     *
     * @param username the username identifying the user whose data is required.
     * @return a fully populated user record (never {@code null})
     * @throws UsernameNotFoundException if the user could not be found or the user has no
     * GrantedAuthority
     */
    @Override
    @Transactional(readOnly = true) // Use read-only transaction for fetching data
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. Fetch your AppUser entity from the database
        AppUser appUser = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        // 2. Convert the roles stored in AppUser (List<String>)
        //    into a collection of GrantedAuthority objects required by Spring Security.
        List<GrantedAuthority> authorities = mapRolesToAuthorities(appUser.getRoles());

        if (authorities.isEmpty()) {
            // Spring Security requires at least one authority.
            // You might want to log a warning here or handle it based on your app's logic.
            // For now, we'll throw an exception as per the UserDetailsService contract.
            throw new UsernameNotFoundException("User " + username + " has no authorities assigned.");
        }


        // 3. Create and return a Spring Security User object (which implements UserDetails)
        return new User(
                appUser.getUsername(),
                appUser.getPassword(),
                authorities
        );
    }

    /**
     * Helper method to convert the List of role strings into a List of GrantedAuthority objects.
     * @param roles List of role strings (e.g., ["ROLE_USER", "ROLE_ADMIN"])
     * @return List of SimpleGrantedAuthority objects
     */
    private List<GrantedAuthority> mapRolesToAuthorities(Collection<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return List.of();
        }
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
