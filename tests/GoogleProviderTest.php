<?php

declare(strict_types=1);

namespace NolvikoExt\Google\Tests;

use Nolviko\Core\Config\Config;
use Nolviko\Core\Config\Secret;
use Nolviko\Core\Extensions\AuthChallenge;
use Nolviko\Core\Extensions\ExtensionFailure;
use NolvikoExt\Google\GoogleProvider;
use NolvikoExt\Google\GoogleSettings;
use PHPUnit\Framework\TestCase;

/**
 * Run from the workspace root (not part of the ZIP):
 *   php dev/vendor/bin/phpunit --bootstrap dev/vendor/autoload.php extensions-src/nolviko/google/tests
 * Google is replaced by a fake token endpoint; the core flow is covered by app/tests/Integration/ExternalAuthTest.
 */
final class GoogleProviderTest extends TestCase
{
    private const NOW = 1_800_000_000;

    private const CLIENT = '1234-abc.apps.googleusercontent.com';

    /** @var array<string, string> */
    private array $sent = [];

    public static function setUpBeforeClass(): void
    {
        require_once dirname(__DIR__) . '/src/GoogleSettings.php';
        require_once dirname(__DIR__) . '/src/GoogleProvider.php';
    }

    public function testAuthorizationAddressCarriesStateNonceAndPkce(): void
    {
        $url = $this->provider([])->authorizationUrl($this->challenge(), 'https://forum.example/cb', 'st4te', 'ch4ll');
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        self::assertStringStartsWith(GoogleProvider::AUTHORIZE . '?', $url);
        self::assertSame(self::CLIENT, $query['client_id']);
        self::assertSame('st4te', $query['state']);
        self::assertSame(str_repeat('a', 64), $query['nonce']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame('openid email profile', $query['scope']);
    }

    public function testAVerifiedGoogleAccountBecomesAnIdentity(): void
    {
        $identity = $this->provider([])
            ->identity($this->challenge(), 'https://forum.example/cb', 'the-code', 'verifier');

        self::assertSame('nolviko/google', $identity->provider);
        self::assertSame('110169484474386276334', $identity->subject);
        self::assertSame('ayse@example.com', $identity->verifiedEmail);
        self::assertSame('Ayşe Yılmaz', $identity->name);
        self::assertSame('verifier', $this->sent['code_verifier']);
        self::assertSame('top-secret', $this->sent['client_secret']);
        self::assertSame('authorization_code', $this->sent['grant_type']);
    }

    public function testAnUnverifiedAddressIsLeftOut(): void
    {
        $identity = $this->provider(['email_verified' => false])
            ->identity($this->challenge(), 'https://forum.example/cb', 'code', 'v');

        self::assertNull($identity->verifiedEmail);
    }

    public function testWrongTokensAreRefused(): void
    {
        foreach (
            [
                ['nonce' => str_repeat('b', 64)],
                ['aud' => 'someone-else.apps.googleusercontent.com'],
                ['iss' => 'https://evil.example'],
                ['exp' => self::NOW - 600],
                ['sub' => 'not-a-number'],
            ] as $changes
        ) {
            try {
                $this->provider($changes)->identity($this->challenge(), 'https://forum.example/cb', 'code', 'v');
                self::fail('accepted ' . (string) json_encode($changes));
            } catch (ExtensionFailure) {
                $this->addToAssertionCount(1);
            }
        }

        $this->expectException(ExtensionFailure::class);
        $refusing = static fn(): array => [400, '{"error":"invalid_grant"}'];
        (new GoogleProvider($this->settings(), $refusing, static fn(): int => self::NOW))
            ->identity($this->challenge(), 'https://forum.example/cb', 'code', 'v');
    }

    public function testWithoutClientSettingsItIsNotOffered(): void
    {
        self::assertFalse((new GoogleProvider(new GoogleSettings(sys_get_temp_dir(), null)))->available());
        self::assertSame(extension_loaded('openssl'), $this->provider([])->available());
    }

    /** @param array<string, mixed> $changes */
    private function provider(array $changes): GoogleProvider
    {
        $claims = $changes + [
            'iss' => 'https://accounts.google.com', 'aud' => self::CLIENT, 'sub' => '110169484474386276334',
            'email' => 'Ayse@Example.com', 'email_verified' => true, 'name' => 'Ayşe Yılmaz',
            'nonce' => str_repeat('a', 64), 'iat' => self::NOW - 5, 'exp' => self::NOW + 3600,
        ];
        $segment = static fn(array $data): string
            => rtrim(strtr(base64_encode((string) json_encode($data)), '+/', '-_'), '=');
        $jwt = $segment(['alg' => 'RS256']) . '.' . $segment($claims) . '.signature';

        return new GoogleProvider(
            $this->settings(),
            function (string $url, array $fields) use ($jwt): array {
                $this->sent = $fields;

                return [$url === GoogleProvider::TOKEN ? 200 : 404, (string) json_encode(['id_token' => $jwt])];
            },
            static fn(): int => self::NOW,
        );
    }

    public function testSettingsFromThePanelAreSealedAndConfigWins(): void
    {
        $directory = sys_get_temp_dir() . '/nolviko-google-' . bin2hex(random_bytes(4));
        mkdir($directory);
        try {
            $plain = new Config('mysql', 'h', null, 'd', 'u', new Secret('x'), new Secret(str_repeat('s', 32)));
            $settings = new GoogleSettings($directory, $plain);
            self::assertNull($settings->client());

            $settings->save('99-x.apps.googleusercontent.com', 'GOCSPX-panel-secret');
            $file = (string) file_get_contents($directory . '/client.json');
            self::assertStringNotContainsString('panel-secret', $file, 'sealed on disk');
            self::assertSame('GOCSPX-panel-secret', $settings->client()['client_secret']->reveal() ?? null);

            $settings->save('99-y.apps.googleusercontent.com', null);
            self::assertSame('99-y.apps.googleusercontent.com', $settings->clientId());
            self::assertSame('GOCSPX-panel-secret', $settings->client()['client_secret']->reveal() ?? null, 'kept');

            $otherKey = new Config('mysql', 'h', null, 'd', 'u', new Secret('x'), new Secret(str_repeat('t', 32)));
            $foreign = new GoogleSettings($directory, $otherKey);
            self::assertNull($foreign->client(), 'another site secret cannot open it');

            $fromFile = new GoogleSettings($directory, $this->config());
            self::assertTrue($fromFile->fromConfig());
            self::assertSame(self::CLIENT, $fromFile->clientId());

            $settings->clear();
            self::assertFalse($settings->hasSecret());
        } finally {
            array_map('unlink', glob($directory . '/*') ?: []);
            rmdir($directory);
        }
    }

    private function settings(): GoogleSettings
    {
        return new GoogleSettings(sys_get_temp_dir(), $this->config());
    }

    private function config(): Config
    {
        return new Config(
            'mysql',
            'localhost',
            null,
            'forum',
            'forum',
            new Secret('x'),
            new Secret(str_repeat('s', 32)),
            oauth: ['google' => ['client_id' => self::CLIENT, 'client_secret' => new Secret('top-secret')]],
        );
    }

    private function challenge(): AuthChallenge
    {
        return new AuthChallenge('nolviko/google', 0, 'sign_in', str_repeat('a', 64), self::NOW + 600);
    }
}
