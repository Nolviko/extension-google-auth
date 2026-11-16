<?php

declare(strict_types=1);

namespace NolvikoExt\Google;

use Nolviko\Core\Config\Config;
use Nolviko\Core\Config\Secret;
use RuntimeException;
use SensitiveParameter;
use Throwable;

/**
 * The Google client entered on the settings page (ADR-034 amendment 2026-11-15): one JSON file in the extension's
 * private storage directory, the secret sealed with a key derived from the site secret. Values in config/local.php
 * or the environment (`oauth.google.*`) win and make the page read-only.
 */
final class GoogleSettings
{
    private const FILE = '/client.json';

    private const PREFIX = 'v1.';

    public function __construct(private readonly string $directory, private readonly ?Config $config)
    {
    }

    /** True when config/local.php or the environment sets the client (the page shows it read-only). */
    public function fromConfig(): bool
    {
        return isset($this->config?->oauth['google']);
    }

    /** @return array{client_id: string, client_secret: Secret}|null */
    public function client(): ?array
    {
        if ($this->fromConfig()) {
            return $this->config->oauth['google'];
        }

        $stored = $this->read();
        $secret = $stored === null ? null : $this->open((string) ($stored['secret'] ?? ''));

        return $stored !== null && ($stored['client_id'] ?? '') !== '' && $secret !== null
            ? ['client_id' => (string) $stored['client_id'], 'client_secret' => new Secret($secret)] : null;
    }

    /** The stored client ID (for the form), or ''. */
    public function clientId(): string
    {
        return $this->fromConfig() ? $this->config->oauth['google']['client_id']
            : (string) ($this->read()['client_id'] ?? '');
    }

    public function hasSecret(): bool
    {
        return $this->client() !== null;
    }

    /** @param string|null $secret Null keeps the stored secret. */
    public function save(string $clientId, #[SensitiveParameter] ?string $secret): void
    {
        $current = $this->read() ?? [];
        $sealed = $secret === null ? (string) ($current['secret'] ?? '') : $this->seal($secret);
        $json = json_encode(
            ['client_id' => $clientId, 'secret' => $sealed],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );
        $temporary = $this->directory . '/.client-' . bin2hex(random_bytes(6)) . '.json';
        $written = file_put_contents($temporary, $json, LOCK_EX) !== false;
        if (!$written || !rename($temporary, $this->directory . self::FILE)) {
            @unlink($temporary);
            throw new RuntimeException('nolviko_google_settings_unwritable');
        }
        @chmod($this->directory . self::FILE, 0600);
    }

    public function clear(): void
    {
        @unlink($this->directory . self::FILE);
    }

    /** @return array<string, mixed>|null */
    private function read(): ?array
    {
        try {
            $raw = is_file($this->directory . self::FILE) ? file_get_contents($this->directory . self::FILE) : false;
            $data = is_string($raw) ? json_decode($raw, true, 4) : null;
        } catch (Throwable) {
            return null;
        }

        return is_array($data) ? $data : null;
    }

    private function seal(#[SensitiveParameter] string $secret): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return self::PREFIX . base64_encode($nonce . sodium_crypto_secretbox($secret, $nonce, $this->key()));
    }

    private function open(string $sealed): ?string
    {
        $raw = str_starts_with($sealed, self::PREFIX)
            ? base64_decode(substr($sealed, strlen(self::PREFIX)), true) : false;
        if (!is_string($raw) || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return null;
        }
        $plain = sodium_crypto_secretbox_open(
            substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            $this->key(),
        );

        return is_string($plain) && $plain !== '' ? $plain : null;
    }

    private function key(): string
    {
        $secret = $this->config?->appSecret->reveal() ?? '';
        if ($secret === '') {
            throw new RuntimeException('nolviko_google_settings_unavailable');
        }

        return hash_hkdf('sha256', $secret, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'nolviko google oauth client');
    }
}
