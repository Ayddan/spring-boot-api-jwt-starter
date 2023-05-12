package api.projet.tda.apiprojettda.auth;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import api.projet.tda.apiprojettda.config.JwtService;
import api.projet.tda.apiprojettda.user.Role;
import api.projet.tda.apiprojettda.user.User;
import api.projet.tda.apiprojettda.user.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    
    public AuthenticationResponse register(RegisterRequest request) {
        if(!repository.findByEmail(request.getEmail()).isPresent()) {
            var user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
            repository.save(user);
            var jwtToken = jwtService.generateToken(user);
            return AuthenticationResponse.builder()
                .token(jwtToken)
                .success(true)
                .message("Successfully registered")
                .build();
        }else{
            return AuthenticationResponse.builder()
                .success(false)
                .message("User with this email already exist")
                .build();
        }
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try{
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getEmail(), 
                    request.getPassword()
                )
            );
        }catch(Exception e){
            return AuthenticationResponse.builder()
            .success(false)
            .message(e.getMessage())
            .build();
        }
        

        var user = repository.findByEmail(request.getEmail())
        .orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
            .token(jwtToken)
            .success(true)
            .message("Successfully connected")
            .build();
    }
    
}
