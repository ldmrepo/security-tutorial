package my.home.securitytutorial.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import my.home.securitytutorial.config.JwtService;
import my.home.securitytutorial.domain.Role;
import my.home.securitytutorial.domain.User;
import my.home.securitytutorial.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;
        private final JwtService jwtService;
        private final AuthenticationManager authenticationManager;

        public AuthenticationResponse register(RegisterRequest registerRequest) {
                User user = User.builder()
                                .firstName(registerRequest.getFirstName())
                                .lastName(registerRequest.getLastName())
                                .email(registerRequest.getEmail())
                                .password(passwordEncoder.encode(registerRequest.getPassword()))
                                .role(Role.USER)
                                .build();
                userRepository.save(user);
                String jwtToken = jwtService.generateToken(user);
                return AuthenticationResponse.builder()
                                .token(jwtToken)
                                .build();
        }

        public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
                authenticationManager
                                .authenticate(new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                                                authenticationRequest.getEmail(),
                                                authenticationRequest.getPassword()));
                User user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
                String jwtToken = jwtService.generateToken(user);
                return AuthenticationResponse.builder()
                                .token(jwtToken)
                                .build();
        }
}
