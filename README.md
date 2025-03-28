# Token Security Starter for Spring Boot
Adds JWT authentication to a Spring Boot application in a simple way.

## Prerequisites
Requires Spring Boot 3.4.4 with the following dependencies:

- `spring-boot-starter-web`
- `spring-boot-starter-security`

The starter is database agnostic and does not assume anything about how user data is persisted.

## Installation
Add the dependency:
```xml
<dependency>
    <groupId>me.forslund.tokensecurity</groupId>
    <artifactId>token-security-starter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

Make sure your application have implementations of the following beans:
- `PasswordEncoder`
- `UserDetailsService`

## Usage
Three new endpoints are added as security filters:
- `POST /login`
- `POST /login/refresh`
- `POST /logout`

### Logging in
The user starts each session by logging in.

```bash
curl -X POST http://localhost:8080/login \
  -c cookies.txt \
  -H 'Content-Type:application/json' \
  -d '{
    "username": "user",
    "password": "password"
  }'
```

**Response**
```text
< HTTP/1.1 202
< Set-Cookie: jwt.token=<generated refresh token>
{
  "accessToken": "<generated access token>"
}
```

### Staying logged in
As long as the refresh token is valid, a new access token can be requested using the refresh endpoint.

```bash
curl -X POST http://localhost:8080/login/refresh \
  -b cookies.txt
```

**Response**
```text
< HTTP/1.1 202
< Set-Cookie: jwt.token=<generated refresh token>
{
  "accessToken": "<generated access token>"
}
```

### Logging out
The refresh cookie can be cleared before its expiration time by calling the logout endpoint.

```bash
curl -X POST http://localhost:8080/logout \
  -b cookies.txt
```

**Response**
```text
< HTTP/1.1 204
< Set-Cookie: jwt.token=; Max-Age=0; Domain=localhost; Path=/; HttpOnly
```

### Calling other endpoints
To invoke any spring endpoint authenticated as a user, simple include the returned accessToken in the `Authorization: Bearer` header:

```bash
curl -X POST http://localhost:8080/profile/me \
  -H Authorization: Bearer <access token>
```

**Response**
```text
< HTTP/1.1 200
{
  "message": "Welcome <b>user</b>!"
}
```

## Example
Here is a minimal example of how to set up the required beans:

```java
@Configuration
public class AppConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
            .username("user")
            .password("{noop}password")
            .authorities("profile:read")
            .build();

        return new InMemoryUserDetailsManager(user);
    }
}
```

## Configuration
The following configuration options are available in the `application.yml` file:

```yaml
jwt:
  enabled: true
  
  bootstrap: true               # Should RSA key pair be generated if missing
  publicKey: jwt_public.pem     # Can be a file, URL or raw key
  privateKey: jwt_private.pem   # <- Same as above
  
  issuer: localhost             # Expected JWT issuer
  audience: localhost           # Expected audience
  scope:                        # Typically empty, but can include a particular
                                # scope like 'profile' if the JWT is issued by 
                                # an external service

  loginUrl: /login              # The login endpoint
  refreshUrl: /login/refresh    # The refresh endpoint
  logoutUrl: /logout            # The logout endpoint

  cookie:
    name: jwt.token             # The name of the refresh token cookie
    domain: localhost           # The domain name to set in the cookie
    secure: false               # Enable secure cookies (good for production
                                # but works poorly locally)
```

## License
Copyright 2025 Emil Forslund

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.