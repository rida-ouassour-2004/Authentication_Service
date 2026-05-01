package com.freelanceplatform.auth.SERVICE;

import com.freelanceplatform.auth.ENTITY.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void sendVerificationEmail(User user, String token) {
        String verifyUrl = "http://localhost:8080/api/v1/auth/verify?token=" + token;
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(user.getEmail());
        message.setSubject("Vérifiez votre adresse e-mail");
        message.setText("Bonjour " + user.getEmail() + ",\n\n" +
                "Merci de vous être inscrit. Veuillez cliquer sur le lien ci-dessous pour activer votre compte :\n"
                + verifyUrl);

        mailSender.send(message);
    }
}

