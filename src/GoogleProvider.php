<?php

declare(strict_types=1);

namespace NolvikoExt\Google;

use Closure;
use Nolviko\Core\Extensions\AuthChallenge;
use Nolviko\Core\Extensions\ExtensionFailure;
use Nolviko\Core\Extensions\ExternalIdentity;
use Nolviko\Core\Extensions\IdentityProvider;
use SensitiveParameter;

/**
 * Sign in with Google (2026-11-15): OpenID Connect authorization-code flow with PKCE, no library. The ID token
 * comes straight from Google's token endpoint over verified TLS, so its claims are checked (issuer, audience,
 * expiry, issue time, nonce) without a signature check (OpenID Connect Core 1.0, 3.1.3.7, point 6). The address
 * counts only when Google marks it verified. Client ID and secret come from the settings page (secret sealed,
 * ADR-034 amendment 2026-11-15) or, winning over it, config/local.php / the environment (`oauth.google.*`).
 */
final class GoogleProvider implements IdentityProvider
{
    public const AUTHORIZE = 'https://accounts.google.com/o/oauth2/v2/auth';

    public const TOKEN = 'https://oauth2.googleapis.com/token';

    private const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

    private readonly Closure $post;

    private readonly Closure $clock;

    /**
     * @param (Closure(string $url, array<string, string> $fields): array{0: int, 1: string})|null $post
     * @param (Closure(): int)|null $clock
     */
    public function __construct(
        private readonly GoogleSettings $settings,
        ?Closure $post = null,
        ?Closure $clock = null,
    ) {
        $this->post = $post ?? self::httpPost(...);
        $this->clock = $clock ?? time(...);
    }

    public function slug(): string
    {
        return 'google';
    }

    public function label(): string
    {
        return 'nolviko.google.button';
    }

    public function available(): bool
    {
        return $this->settings->client() !== null && extension_loaded('openssl');
    }

    public function authorizationUrl(
        AuthChallenge $challenge,
        string $redirectUri,
        string $state,
        string $codeChallenge,
    ): string {
        return self::AUTHORIZE . '?' . http_build_query([
            'client_id' => $this->client()['client_id'],
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $state,
            'nonce' => $challenge->nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
            'prompt' => 'select_account',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public function identity(
        AuthChallenge $challenge,
        string $redirectUri,
        #[SensitiveParameter] string $code,
        #[SensitiveParameter] string $codeVerifier,
    ): ExternalIdentity {
        $client = $this->client();
        [$status, $body] = ($this->post)(self::TOKEN, [
            'code' => $code,
            'client_id' => $client['client_id'],
            'client_secret' => $client['client_secret']->reveal(),
            'redirect_uri' => $redirectUri,
            'grant_type' => 'authorization_code',
            'code_verifier' => $codeVerifier,
        ]);
        $token = $status === 200 ? json_decode($body, true, 8) : null;
        if (!is_array($token) || !is_string($token['id_token'] ?? null)) {
            throw new ExtensionFailure('google_token_rejected');
        }

        $claims = self::claims($token['id_token']);
        $now = ($this->clock)();
        if (
            !in_array($claims['iss'] ?? null, self::ISSUERS, true)
            || ($claims['aud'] ?? null) !== $client['client_id']
            || !is_int($claims['exp'] ?? null) || $claims['exp'] < $now - 60
            || !is_int($claims['iat'] ?? null) || $claims['iat'] > $now + 300
            || !is_string($claims['nonce'] ?? null) || !hash_equals($challenge->nonce, $claims['nonce'])
            || !is_string($claims['sub'] ?? null) || preg_match('/^[0-9]{1,64}$/D', $claims['sub']) !== 1
        ) {
            throw new ExtensionFailure('google_token_invalid');
        }

        $email = is_string($claims['email'] ?? null) && ($claims['email_verified'] ?? false) === true
            ? strtolower($claims['email']) : null;

        return new ExternalIdentity(
            $challenge->provider,
            $claims['sub'],
            $email !== null && filter_var($email, FILTER_VALIDATE_EMAIL) !== false ? $email : null,
            is_string($claims['name'] ?? null) ? mb_substr($claims['name'], 0, 80) : '',
        );
    }

    /** @return array<string, mixed> The payload of a JWT (header and signature are not used, see the class note). */
    public static function claims(string $jwt): array
    {
        $parts = explode('.', $jwt);
        $json = count($parts) === 3 && strlen($jwt) <= 8192
            ? base64_decode(strtr($parts[1], '-_', '+/'), true) : false;
        $claims = is_string($json) ? json_decode($json, true, 8) : null;
        if (!is_array($claims)) {
            throw new ExtensionFailure('google_token_invalid');
        }

        return $claims;
    }

    /** @return array{client_id: string, client_secret: \Nolviko\Core\Config\Secret} */
    private function client(): array
    {
        return $this->settings->client() ?? throw new ExtensionFailure('google_not_configured');
    }

    /**
     * POST over HTTPS with certificate checks and a 10-second limit.
     *
     * @param array<string, string> $fields
     *
     * @return array{0: int, 1: string} Status and body (0 and '' when the request failed).
     */
    private static function httpPost(string $url, #[SensitiveParameter] array $fields): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n",
                'content' => http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
                'timeout' => 10,
                'ignore_errors' => true,
                'follow_location' => 0,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        $body = @file_get_contents($url, false, $context, 0, 65536);
        $status = 0;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $match) === 1) {
                $status = (int) $match[1];
            }
        }

        return [$status, is_string($body) ? $body : ''];
    }
}
