package cc.conyli.jwtfilter.jwt;

import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;

@Component
public class JWTUtils {

    private static String BASE_SECRET_STRING = "dSF*F*()SD)(*()9032190898gfsd980*(F*(DS(*()*#@*(*#()!@*()#*(!)@";

    private static final Key KEY = Keys.hmacShaKeyFor(BASE_SECRET_STRING.getBytes());

    public static String AUTH_LOGIN_URL = "/api/auth";

    public static String TOKEN_HEADER = "Authorization";

    public static String TOKEN_ISSUER = "conyli.cc";

    public static Key getKey() {
        return JWTUtils.KEY;
    }

    public String getKeyString() {
        return Base64.getEncoder().encodeToString(KEY.getEncoded());
    }
}
