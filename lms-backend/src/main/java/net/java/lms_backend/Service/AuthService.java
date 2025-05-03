package net.java.lms_backend.Service;

import net.java.lms_backend.Repositrory.EmailSender;
import net.java.lms_backend.Repositrory.UserRepository;
import net.java.lms_backend.Security.Jwt.JwtTokenProvider;
import net.java.lms_backend.dto.LoginRequestDTO;
import net.java.lms_backend.dto.RegisterDTO;
import net.java.lms_backend.entity.ConfirmationToken;
import net.java.lms_backend.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import static net.java.lms_backend.mapper.UserMapper.ToUserLogin;
import static net.java.lms_backend.mapper.UserMapper.ToUserRegister;

@Service
public class AuthService {
    private final UserService userService;
    private final ConfirmationTokenService confirmationTokenService;
    private final EmailSender emailSender;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
//    private final JwtTokenProvider tokenProvider;
//    private final AuthenticationManager authenticationManager;
    public AuthService(UserService userService, EmailValidatorService emailValidatorService, ConfirmationTokenService confirmationTokenService, EmailSender emailSender, UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userService = userService;
        this.confirmationTokenService = confirmationTokenService;
        this.emailSender = emailSender;
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
//        this.tokenProvider = tokenProvider;
//        this.authenticationManager = authenticationManager;
    }

    public ResponseEntity<String> register(RegisterDTO user) {
        ResponseEntity<String> ret= userService.signUpUser(ToUserRegister(user));
        if(ret.getStatusCode().equals(HttpStatus.OK)){
            String token=ret.getBody();
            String link = "http://localhost:9090/api/auth/confirm?token="+token;
            emailSender.send(
                    user.getEmail(),
                    buildEmail(user.getFirstname(), link));
            ret= ResponseEntity.status(HttpStatus.CREATED).body("Thank you for registering with us! " +
                    "We're excited to have you onboard.\n" +
                    "To complete your registration, please check your email for the activation " +
                    "link. Click the link in the email to activate your account and start using our services.");
        }
        return ret;

    }

    @Transactional
    public ResponseEntity<String> confirmToken(String token) {
        ConfirmationToken confirmationToken = confirmationTokenService
                .getToken(token)
                .orElseThrow(() ->
                        new IllegalStateException("link not found"));

        if (confirmationToken.getConfirmedDate() != null) {
            return  ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE)
                    .body("User already confirmed");
        }

        LocalDateTime expiredDate = confirmationToken.getExpiresDate();

        if (expiredDate.isBefore(LocalDateTime.now())) {
            ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT)
                    .body("Link expired");
        }

        confirmationTokenService.setConfirmedToken(token);
        userService.enableUser(
                confirmationToken.getUser().getEmail());
        return ResponseEntity.ok("User successfully confirmed");
    }
    private String buildEmail(String name, String link) {
        return "<div style=\"font-family:Helvetica,Arial,sans-serif;font-size:16px;margin:0;color:#0b0c0c\">\n" +
                "\n" +
                "<span style=\"display:none;font-size:1px;color:#fff;max-height:0\"></span>\n" +
                "\n" +
                "  <table role=\"presentation\" width=\"100%\" style=\"border-collapse:collapse;min-width:100%;width:100%!important\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">\n" +
                "    <tbody><tr>\n" +
                "      <td width=\"100%\" height=\"53\" bgcolor=\"#0b0c0c\">\n" +
                "        \n" +
                "        <table role=\"presentation\" width=\"100%\" style=\"border-collapse:collapse;max-width:580px\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" align=\"center\">\n" +
                "          <tbody><tr>\n" +
                "            <td width=\"70\" bgcolor=\"#0b0c0c\" valign=\"middle\">\n" +
                "                <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse\">\n" +
                "                  <tbody><tr>\n" +
                "                    <td style=\"padding-left:10px\">\n" +
                "                  \n" +
                "                    </td>\n" +
                "                    <td style=\"font-size:28px;line-height:1.315789474;Margin-top:4px;padding-left:10px\">\n" +
                "                      <span style=\"font-family:Helvetica,Arial,sans-serif;font-weight:700;color:#ffffff;text-decoration:none;vertical-align:top;display:inline-block\">Confirm your email</span>\n" +
                "                    </td>\n" +
                "                  </tr>\n" +
                "                </tbody></table>\n" +
                "              </a>\n" +
                "            </td>\n" +
                "          </tr>\n" +
                "        </tbody></table>\n" +
                "        \n" +
                "      </td>\n" +
                "    </tr>\n" +
                "  </tbody></table>\n" +
                "  <table role=\"presentation\" class=\"m_-6186904992287805515content\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse;max-width:580px;width:100%!important\" width=\"100%\">\n" +
                "    <tbody><tr>\n" +
                "      <td width=\"10\" height=\"10\" valign=\"middle\"></td>\n" +
                "      <td>\n" +
                "        \n" +
                "                <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse\">\n" +
                "                  <tbody><tr>\n" +
                "                    <td bgcolor=\"#1D70B8\" width=\"100%\" height=\"10\"></td>\n" +
                "                  </tr>\n" +
                "                </tbody></table>\n" +
                "        \n" +
                "      </td>\n" +
                "      <td width=\"10\" valign=\"middle\" height=\"10\"></td>\n" +
                "    </tr>\n" +
                "  </tbody></table>\n" +
                "\n" +
                "\n" +
                "\n" +
                "  <table role=\"presentation\" class=\"m_-6186904992287805515content\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse;max-width:580px;width:100%!important\" width=\"100%\">\n" +
                "    <tbody><tr>\n" +
                "      <td height=\"30\"><br></td>\n" +
                "    </tr>\n" +
                "    <tr>\n" +
                "      <td width=\"10\" valign=\"middle\"><br></td>\n" +
                "      <td style=\"font-family:Helvetica,Arial,sans-serif;font-size:19px;line-height:1.315789474;max-width:560px\">\n" +
                "        \n" +
                "            <p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\">Hi " + name + ",</p><p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\"> Thank you for registering. Please click on the below link to activate your account: </p><blockquote style=\"Margin:0 0 20px 0;border-left:10px solid #b1b4b6;padding:15px 0 0.1px 15px;font-size:19px;line-height:25px\"><p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\"> <a href=\"" + link + "\">Activate Now</a> </p></blockquote>\n Link will expire in 5 minutes. <p>See you soon</p>" +
                "        \n" +
                "      </td>\n" +
                "      <td width=\"10\" valign=\"middle\"><br></td>\n" +
                "    </tr>\n" +
                "    <tr>\n" +
                "      <td height=\"30\"><br></td>\n" +
                "    </tr>\n" +
                "  </tbody></table><div class=\"yj6qo\"></div><div class=\"adL\">\n" +
                "\n" +
                "</div></div>";
    }

    public ResponseEntity<String> Login(User userRequest) {
        Optional<User> optionalUser = userRepository.findByUsername(userRequest.getUsername());
        if (optionalUser.isEmpty()) {
            optionalUser = userRepository.findByEmail(userRequest.getEmail());
        }

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (bCryptPasswordEncoder.matches(userRequest.getPassword(), user.getPassword())) {
                if(user.isEnabled()) {
//                    authenticationManager.authenticate(
//                            new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
//                    );
//
//                    List<String> roles = new ArrayList<>();
//                    roles.add(user.getRole().name());
//
//                    String token = tokenProvider.generateToken(user.getUsername(), roles);
//                    return ResponseEntity.ok("Bearer " + token);
                        return ResponseEntity.ok("Successfully logged in");
                } else {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User is not enabled");
                }
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("Invalid Username, Email or Password");
            }
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Invalid Username, Email or Password");
        }
    }

}
