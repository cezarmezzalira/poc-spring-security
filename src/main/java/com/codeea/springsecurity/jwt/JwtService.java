package com.codeea.springsecurity.jwt;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;

@Service
public class JwtService {

    private final String SECRET_KEY = "zHmr6aOr022AX8gpM7hfDMRj6h8X/72suZrNsib4rt4=";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);

        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails) {
        final Integer expirationMillis = 1000 * 60 * 24;
        final String token = Jwts
                .builder()
                .claims()
                .add(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationMillis))
                .and()
                .signWith(getSignInKey())
                .compact();
        return token;
    }

    private Claims extractAllClaims(String token) {
        final JwtParser parser = Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build();

        return parser
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKeySpec getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, Jwts.SIG.HS256.getId());
        return secretKeySpec;
    }
}
