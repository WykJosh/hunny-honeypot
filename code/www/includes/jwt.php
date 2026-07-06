<?php
// includes/jwt.php
// Pure-PHP JWT helper — no external library needed (Lab 7 pattern)
// Secrets are loaded from /etc/honeypot/db.env via config.php before this file is included

function jwt_base64url(string $data): string
{
    return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
}

function jwt_generate(array $user): string
{
    $secret  = getenv('JWT_SECRET') ?: 'fallback-secret-change-me';
    $issuer  = getenv('JWT_ISSUER') ?: 'https://group04.hp.edu.technet.howest.be';
    $ttl     = (int)(getenv('JWT_TTL') ?: 3600);

    $header  = jwt_base64url(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));

    $payload = jwt_base64url(json_encode([
        'iss'      => $issuer,
        'iat'      => time(),
        'exp'      => time() + $ttl,
        'sub'      => (string)($user['id'] ?? 0),
        'username' => $user['username'] ?? '',
        'admin'    => (bool)($user['is_admin'] ?? false),
    ]));

    $signature = jwt_base64url(
        hash_hmac('sha256', $header . '.' . $payload, $secret, true)
    );

    return $header . '.' . $payload . '.' . $signature;
}

function jwt_verify(string $token): ?array
{
    $secret = getenv('JWT_SECRET') ?: 'fallback-secret-change-me';
    $parts  = explode('.', $token);

    if (count($parts) !== 3) return null;

    [$header, $payload, $sig] = $parts;

    $expected = jwt_base64url(
        hash_hmac('sha256', $header . '.' . $payload, $secret, true)
    );

    // Constant-time comparison — prevents timing attacks
    if (!hash_equals($expected, $sig)) return null;

    $claims = json_decode(
        base64_decode(str_replace(['-', '_'], ['+', '/'], $payload)),
        true
    );

    if (!$claims) return null;
    if (($claims['exp'] ?? 0) < time()) return null;  // expired

    return $claims;
}

function jwt_from_request(): ?string
{
    // Check Authorization: Bearer <token> header first
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (str_starts_with($auth, 'Bearer ')) {
        return substr($auth, 7);
    }
    // Fallback: httpOnly cookie named 'jwt'
    return $_COOKIE['jwt'] ?? null;
}

function require_jwt_auth(): array
{
    $token  = jwt_from_request();
    $claims = $token ? jwt_verify($token) : null;

    if (!$claims) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }

    return $claims;
}