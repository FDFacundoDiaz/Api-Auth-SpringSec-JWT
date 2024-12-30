package com.springsecurity.utils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.security.core.Authentication;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    //Configuraciones para asegurar la autenticidad del token a crear
    @Value("${security.jwt.private.key}")
    private String privateKey;

    @Value("${security.jwt.user.generator}")
    private String userGenerator;

    //Para encriptar, vamos a necesitar esta clave secreta y este algoritmo
    public String createToken (Authentication authentication) {
        Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

        //Dentro del security context holder
        String username = authentication.getPrincipal().toString();

        //Obtención de los permisos/autorizaciones
        //Treyendo los permisos separados por coma
        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        //a partir de esto generamos el token
        String jwtToken = JWT.create()
                .withIssuer(this.userGenerator) //Usuario generador del token
                .withSubject(username) //Usuario a quien se le genera el token
                .withClaim("authorities", authorities) //Datos contraidos en el JWT
                .withIssuedAt(new Date()) //Fecha de generación del token
                .withExpiresAt(new Date(System.currentTimeMillis() + 1800000)) //Fecha de expiración
                .withJWTId(UUID.randomUUID().toString()) //Id al token - que genere una random
                .withNotBefore(new Date (System.currentTimeMillis())) //Desde cuando es válido
                .sign(algorithm); //Firma con la clave privada

        return jwtToken;
    }

    //método para decodificar
    public DecodedJWT validateToken(String token) {

        try {
            Algorithm algorithm = Algorithm.HMAC256(this.privateKey); //algoritmo + clave privada
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(this.userGenerator)
                    .build(); //usa patrón builder

            //si está todo ok, no genera excepción y hace el return
            DecodedJWT decodedJWT = verifier.verify(token);
             return decodedJWT;
        }
        catch (JWTVerificationException exception) {
            throw new JWTVerificationException("Invalid token. Not authorized");
        }
    }

    public String extractUsername (DecodedJWT decodedJWT) {
        //El subject es el usuario según establecimos al crear el token
        return decodedJWT.getSubject().toString();
    }

    //Devuelve un claim en particular
    public Claim getSpecificClaim (DecodedJWT decodedJWT, String claimName) {
        return decodedJWT.getClaim(claimName);
    }

    //Devuele todos los claims
    public Map<String, Claim> returnAllClaims (DecodedJWT decodedJWT){
        return decodedJWT.getClaims();
    }
}
