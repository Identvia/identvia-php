<?php
declare(strict_types=1);

namespace Identvia\Sdk\Tests;

use Identvia\Sdk\Cache\FileCache;
use Identvia\Sdk\Cache\MemoryCache;
use Identvia\Sdk\Exception\AuthorizationException;
use Identvia\Sdk\Exception\ConfigurationException;
use Identvia\Sdk\Exception\InvalidStateException;
use Identvia\Sdk\Exception\TokenException;
use Identvia\Sdk\Exception\ValidationException;
use Identvia\Sdk\Identvia;
use Identvia\Sdk\State\MemoryStateStore;
use Identvia\Sdk\State\SessionStateStore;
use PHPUnit\Framework\TestCase;

final class IdentviaTest extends TestCase
{
    private FakeIdentvia $idp;
    private MemoryStateStore $store;
    private MemoryCache $cache;

    protected function setUp(): void
    {
        $this->idp = new FakeIdentvia();
        $this->store = new MemoryStateStore();
        $this->cache = new MemoryCache();
    }

    private function sdk(array $o = []): Identvia
    {
        return new Identvia($o + [
            'issuer' => FakeIdentvia::ISSUER, 'client_id' => FakeIdentvia::CLIENT, 'client_secret' => FakeIdentvia::SECRET,
            'redirect_uri' => FakeIdentvia::REDIRECT, 'http' => $this->idp, 'cache' => $this->cache, 'state_store' => $this->store,
            'clock' => fn () => $this->idp->now,
        ]);
    }

    /** Runs authorize → "user approves" → returns the callback query. */
    private function approve(Identvia $sdk, array $opts = [], array $extra = []): array
    {
        $url = $sdk->authorizationUrl($opts);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        $code = $this->idp->issueCode($q['code_challenge'], $q['nonce']);
        return array_merge(['code' => $code, 'state' => $q['state'], 'iss' => FakeIdentvia::ISSUER], $extra);
    }

    private function lastTo(string $path): array
    {
        $m = array_values(array_filter($this->idp->requests, fn ($r) => str_ends_with(strtok($r['url'], '?'), $path)));
        return end($m) ?: [];
    }

    public function testAuthorizationUrlUsesPkceStateAndNonce(): void
    {
        $url = $this->sdk()->authorizationUrl(['return_to' => '/notes?x=1', 'max_age' => 300, 'prompt' => 'login']);
        $this->assertStringStartsWith(FakeIdentvia::ISSUER . '/oauth/authorize?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        $this->assertSame('code', $q['response_type']);
        $this->assertSame('S256', $q['code_challenge_method']);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $q['code_challenge']);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $q['state']);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $q['nonce']);
        $this->assertSame('openid email profile', $q['scope']);
        $this->assertSame('300', $q['max_age']);
        $this->assertSame('login', $q['prompt']);
        $this->assertArrayNotHasKey('client_secret', $q);
        $saved = $this->store->items[$q['state']];
        $this->assertSame($q['nonce'], $saved['nonce']);
        $this->assertSame('/notes?x=1', $saved['return_to']);
        $this->assertSame(64, strlen($saved['verifier']));
        $this->assertSame($q['code_challenge'], rtrim(strtr(base64_encode(hash('sha256', $saved['verifier'], true)), '+/', '-_'), '='));
    }

    public function testFullSignIn(): void
    {
        $sdk = $this->sdk();
        $r = $sdk->handleCallback($this->approve($sdk, ['return_to' => '/dashboard']));
        $this->assertSame('pw_user_123', $r->sub());
        $this->assertSame('ada@example.test', $r->email());
        $this->assertTrue($r->emailVerified());
        $this->assertSame(['hwk', 'user'], $r->amr());
        $this->assertSame('/dashboard', $r->returnTo);
        $this->assertSame('rt_1', $r->tokens->refreshToken);
        $this->assertFalse($r->tokens->expired());
        $tok = array_values(array_filter($this->idp->requests, fn ($q) => str_ends_with($q['url'], '/oauth/token')))[0];
        $this->assertSame('Basic ' . base64_encode(FakeIdentvia::CLIENT . ':' . FakeIdentvia::SECRET), $tok['headers']['Authorization']);
        $this->assertStringNotContainsString('client_secret', (string) $tok['body']);
    }

    public function testStateIsSingleUse(): void
    {
        $sdk = $this->sdk();
        $q = $this->approve($sdk);
        $sdk->handleCallback($q);
        $this->expectException(InvalidStateException::class);
        $sdk->handleCallback($q);
    }

    public function testUnknownAndMissingStateRejected(): void
    {
        $sdk = $this->sdk();
        $q = $this->approve($sdk);
        foreach ([['state' => 'forged'] + $q, array_diff_key($q, ['state' => 1])] as $bad) {
            try { $sdk->handleCallback($bad); $this->fail('accepted'); } catch (InvalidStateException) { $this->addToAssertionCount(1); }
        }
        $this->assertSame(0, $this->idp->count('/oauth/token'), 'no code exchange without a valid state');
    }

    public function testMultipleTabsCanSignInConcurrently(): void
    {
        $sdk = $this->sdk();
        $a = $this->approve($sdk, ['return_to' => '/a']);
        $b = $this->approve($sdk, ['return_to' => '/b']);
        $this->assertSame('/b', $sdk->handleCallback($b)->returnTo);
        $this->assertSame('/a', $sdk->handleCallback($a)->returnTo);
    }

    public function testIssuerMixUpDefence(): void
    {
        $sdk = $this->sdk();
        try { $sdk->handleCallback($this->approve($sdk, [], ['iss' => 'https://evil.example'])); $this->fail(); } catch (InvalidStateException $e) { $this->assertStringContainsString('different issuer', $e->getMessage()); }
        $q = $this->approve($sdk); unset($q['iss']);
        $this->expectException(InvalidStateException::class);
        $sdk->handleCallback($q);
    }

    public function testUserCancelled(): void
    {
        $sdk = $this->sdk();
        $q = $this->approve($sdk, ['return_to' => '/x']);
        unset($q['code']);
        try {
            $sdk->handleCallback($q + ['error' => 'access_denied', 'error_description' => 'The user declined']);
            $this->fail();
        } catch (AuthorizationException $e) {
            $this->assertTrue($e->userCancelled());
            $this->assertSame('/x', $e->returnTo);
        }
    }

    public function testNonceMismatchRejected(): void
    {
        $sdk = $this->sdk();
        $this->idp->idTokenOverride = $this->idp->idToken(['nonce' => 'someone-elses-nonce']);
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('nonce');
        $sdk->handleCallback($this->approve($sdk));
    }

    public function testMissingNonceRejected(): void
    {
        $sdk = $this->sdk();
        $this->idp->idTokenOverride = $this->idp->idToken(['nonce' => null]);
        $this->expectException(ValidationException::class);
        $sdk->handleCallback($this->approve($sdk));
    }

    /** @return iterable<string, array{0: array}> */
    public static function badClaims(): iterable
    {
        yield 'wrong issuer' => [['iss' => 'https://evil.example']];
        yield 'wrong audience' => [['aud' => 'oid_other']];
        yield 'multi aud without azp' => [['aud' => [FakeIdentvia::CLIENT, 'oid_other'], 'azp' => null]];
        yield 'wrong azp' => [['azp' => 'oid_other']];
        yield 'expired' => [['exp' => time() - 3600, 'iat' => time() - 4000]];
        yield 'issued in the future' => [['iat' => time() + 3600, 'exp' => time() + 7200]];
        yield 'no subject' => [['sub' => '']];
        yield 'at_hash mismatch' => [['at_hash' => 'AAAAAAAAAAAAAAAAAAAAAA']];
    }

    /** @dataProvider badClaims */
    public function testBadIdTokensRejected(array $claims): void
    {
        $sdk = $this->sdk();
        $q = $this->approve($sdk);
        $nonce = array_values($this->idp->codes)[0]['nonce'];
        $this->idp->idTokenOverride = $this->idp->idToken($claims + ['nonce' => $nonce]);
        $this->expectException(ValidationException::class);
        $sdk->handleCallback($q);
    }

    public function testSymmetricAndUnsignedTokensRejected(): void
    {
        $v = $this->sdk()->validator();
        $b = fn ($a) => rtrim(strtr(base64_encode((string) json_encode($a)), '+/', '-_'), '=');
        $claims = ['iss' => FakeIdentvia::ISSUER, 'aud' => FakeIdentvia::CLIENT, 'sub' => 'x', 'iat' => time(), 'exp' => time() + 60];
        $hs = \Firebase\JWT\JWT::encode($claims, FakeIdentvia::SECRET . str_repeat('x', 32), 'HS256', 'rsa-1');
        $none = $b(['alg' => 'none', 'kid' => 'rsa-1']) . '.' . $b($claims) . '.';
        foreach ([$hs, $none, 'not-a-jwt'] as $t) {
            try { $v->validate($t); $this->fail('accepted ' . $t); } catch (ValidationException) { $this->addToAssertionCount(1); }
        }
    }

    public function testTamperedSignatureRejected(): void
    {
        $t = $this->idp->idToken();
        [$h, $p, $s] = explode('.', $t);
        $claims = json_decode(base64_decode(strtr($p, '-_', '+/')), true);
        $claims['sub'] = 'pw_admin';
        $p2 = rtrim(strtr(base64_encode((string) json_encode($claims)), '+/', '-_'), '=');
        $this->expectException(ValidationException::class);
        $this->sdk()->validator()->validate("$h.$p2.$s");
    }

    public function testJwksIsCachedAndRefetchedOnKeyRotation(): void
    {
        $sdk = $this->sdk();
        $sdk->handleCallback($this->approve($sdk));
        $sdk->handleCallback($this->approve($sdk));
        $this->assertSame(1, $this->idp->count('/oauth/jwks.json'), 'JWKS fetched once and cached');
        $this->assertSame(1, $this->idp->count('/.well-known/'), 'discovery cached');

        // Identvia rotates to a new key after the minute-long refetch guard expires
        $this->cache->delete('jwks:' . FakeIdentvia::ISSUER . ':refetched');
        $this->idp->addKey('ec-2', 'ES256');
        $this->idp->signKid = 'ec-2';
        $r = $sdk->handleCallback($this->approve($sdk));
        $this->assertSame('pw_user_123', $r->sub());
        $this->assertSame(2, $this->idp->count('/oauth/jwks.json'), 'refetched once for the unknown kid');

        // An unknown kid right after a refetch does not hammer the JWKS endpoint
        $this->idp->addKey('rogue', 'RS256', false);
        try { $sdk->validator()->validate($this->idp->idToken([], 'rogue')); $this->fail(); } catch (ValidationException $e) { $this->assertStringContainsString('unknown key', $e->getMessage()); }
        $this->assertSame(2, $this->idp->count('/oauth/jwks.json'));
    }

    public function testMaxAgeEnforced(): void
    {
        $sdk = $this->sdk();
        $q = $this->approve($sdk, ['max_age' => 60]);
        $nonce = array_values($this->idp->codes)[0]['nonce'];
        $this->idp->idTokenOverride = $this->idp->idToken(['nonce' => $nonce, 'auth_time' => time() - 3600]);
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('max_age');
        $sdk->handleCallback($q);
    }

    public function testTokenErrorsSurface(): void
    {
        $sdk = $this->sdk();
        $this->idp->tokenError = ['error' => 'invalid_grant', 'error_description' => 'Code expired'];
        try { $sdk->handleCallback($this->approve($sdk)); $this->fail(); } catch (TokenException $e) { $this->assertSame('invalid_grant', $e->error); $this->assertSame(400, $e->status); }
        $this->idp->tokenError = null;
        $bad = $this->sdk(['client_secret' => 'ivs_wrong']);
        try { $bad->handleCallback($this->approve($bad)); $this->fail(); } catch (TokenException $e) { $this->assertSame('invalid_client', $e->error); }
    }

    public function testClientSecretPostAndPublicClients(): void
    {
        $post = $this->sdk(['token_auth' => 'client_secret_post']);
        $post->handleCallback($this->approve($post));
        $last = $this->lastTo('/oauth/token');
        $this->assertArrayNotHasKey('Authorization', $last['headers']);
        $this->assertStringContainsString('client_secret=', (string) $last['body']);

        $pub = $this->sdk(['client_secret' => null]);
        $this->assertSame('pw_user_123', $pub->handleCallback($this->approve($pub))->sub());
        $last = $this->lastTo('/oauth/token');
        $this->assertStringNotContainsString('client_secret', (string) $last['body']);
        $this->assertStringContainsString('client_id=' . FakeIdentvia::CLIENT, (string) $last['body']);
    }

    public function testUserinfoRefreshRevokeLogout(): void
    {
        $sdk = $this->sdk();
        $r = $sdk->handleCallback($this->approve($sdk));
        $this->assertSame('ada@example.test', $sdk->userinfo($r->tokens->accessToken, $r->sub())['email']);
        try { $sdk->userinfo($r->tokens->accessToken, 'pw_someone_else'); $this->fail(); } catch (ValidationException) { $this->addToAssertionCount(1); }
        try { $sdk->userinfo('bogus'); $this->fail(); } catch (TokenException $e) { $this->assertSame(401, $e->status); }
        $t = $sdk->refresh('rt_1', $r->sub());
        $this->assertSame('rt_2', $t->refreshToken);
        try { $sdk->refresh('rt_1', 'pw_other'); $this->fail(); } catch (ValidationException) { $this->addToAssertionCount(1); }
        $sdk->revoke('rt_2');
        $this->assertSame(1, $this->idp->count('/oauth/revoke'));
        $url = $sdk->logoutUrl($r->tokens->idToken, 'https://app.example.test/', 'abc');
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        $this->assertSame(FakeIdentvia::CLIENT, $q['client_id']);
        $this->assertSame('https://app.example.test/', $q['post_logout_redirect_uri']);
    }

    public function testDiscoveryForAnotherIssuerRejected(): void
    {
        $this->idp->discoveryOverride = ['issuer' => 'https://evil.example'];
        $this->expectException(ConfigurationException::class);
        $this->sdk()->authorizationUrl();
    }

    public function testConfigurationValidation(): void
    {
        foreach ([['issuer' => 'http://id.example.com'], ['redirect_uri' => 'http://app.example.com/cb'], ['client_id' => ''], ['token_auth' => 'private_key_jwt']] as $bad) {
            try { $this->sdk($bad); $this->fail(json_encode($bad)); } catch (ConfigurationException) { $this->addToAssertionCount(1); }
        }
        $this->assertSame('http://localhost:8080', $this->sdk(['issuer' => 'http://localhost:8080/', 'redirect_uri' => 'http://localhost:9999/cb'])->issuer());
    }

    public function testReturnToCannotBeAnOpenRedirect(): void
    {
        foreach (['https://evil.example', '//evil.example', '/\\evil.example', "/ok\r\nSet-Cookie: x", 'javascript:alert(1)', 'relative'] as $bad) {
            $this->assertNull(Identvia::safeReturnTo($bad), $bad);
        }
        $this->assertSame('/notes?id=4#top', Identvia::safeReturnTo('/notes?id=4#top'));
    }

    public function testFileCache(): void
    {
        $dir = sys_get_temp_dir() . '/idv-cache-test-' . bin2hex(random_bytes(4));
        $c = new FileCache($dir);
        $c->set('k', '{"a":1}', 60);
        $this->assertSame('{"a":1}', $c->get('k'));
        $c->set('old', 'x', -1);
        $this->assertNull($c->get('old'));
        $c->delete('k');
        $this->assertNull($c->get('k'));
        $this->assertSame('0700', substr(sprintf('%o', fileperms($dir)), -4));
        array_map('unlink', glob("$dir/*") ?: []); rmdir($dir);
    }

    /** @runInSeparateProcess */
    public function testSessionStateStore(): void
    {
        $_SESSION = [];
        session_id('test' . bin2hex(random_bytes(8)));
        @session_start();
        $s = new SessionStateStore();
        $s->put('a', ['n' => 1]);
        $s->put('b', ['n' => 2]);
        $this->assertSame(['n' => 2], $s->pull('b'));
        $this->assertNull($s->pull('b'), 'single use');
        $this->assertArrayNotHasKey('a', $_SESSION[SessionStateStore::KEY], 'state values are stored hashed');
        $_SESSION[SessionStateStore::KEY][hash('sha256', 'a')]['t'] = time() - 601;
        $this->assertNull($s->pull('a'), 'expired after 10 minutes');
        for ($i = 0; $i < 15; $i++) { $s->put("s$i", []); }
        $this->assertCount(SessionStateStore::MAX, $_SESSION[SessionStateStore::KEY]);
        $this->assertNotNull($s->pull('s14'));
        $this->assertNull($s->pull('s0'), 'oldest evicted');
    }
}
