<?php

declare(strict_types=1);

namespace NolvikoExt\Google;

use Nolviko\Core\Http\ErrorResponder;
use Nolviko\Core\Http\InstallerPage;
use Nolviko\Core\Http\RouteHandler;
use Nolviko\Core\Locale\MessageTranslator;
use Nolviko\Core\Routing\CoreRoutes;
use Nolviko\Core\Routing\Router;
use Nolviko\Core\Session\CsrfTokens;
use Nolviko\Core\Session\Session;
use Nolviko\Core\View\SafeHtml;
use Nolviko\Core\View\TemplateRenderer;
use Nolviko\Modules\Admin\Http\AdminNavigation;
use Nolviko\Modules\Admin\Http\AdminSession;
use Nolviko\Modules\Admin\Infrastructure\DbalAdminAudit;
use Nolviko\Modules\Seo\Domain\SiteUrl;
use Nolviko\Modules\Users\Http\RequestSubject;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * `/extensions/nolviko/google/admin` (owner decision 2026-11-15): the site owner sets up Sign in with Google without
 * touching files. Shows the address to register at Google, takes the client ID and secret (the secret is sealed and
 * never shown again; an empty field keeps it) and can remove them. Administrators only, with a password confirmation
 * from the last 15 minutes; every change is audited. Values from config/local.php win and are shown read-only.
 */
final class AdminHandler implements RouteHandler
{
    public const ROUTE = 'nolviko.google.admin';

    private const FLASH = '_nolviko_google_notice';

    private const CONSOLE = 'https://console.cloud.google.com/apis/credentials';

    public function __construct(
        private readonly MessageTranslator $translator,
        private readonly TemplateRenderer $views,
        private readonly RequestSubject $subjects,
        private readonly AdminSession $admin,
        private readonly CsrfTokens $csrf,
        private readonly Router $router,
        private readonly Session $session,
        private readonly DbalAdminAudit $audit,
        private readonly ErrorResponder $errors,
        private readonly SiteUrl $site,
        private readonly GoogleSettings $settings,
    ) {
    }

    public function handle(Request $request, array $parameters): Response
    {
        $subject = $this->subjects->of($request);
        if ($subject->userId === null || !$subject->allows('admin.access')) {
            return $subject->userId === null
                ? InstallerPage::redirect($this->router->generate(CoreRoutes::LOGIN)) : $this->errors->denied();
        }

        $error = null;
        if ($request->isMethod('POST')) {
            if (!$this->admin->isFresh()) {
                $error = $this->text('reauth');
            } elseif ($this->settings->fromConfig()) {
                $error = $this->text('from_config');
            } else {
                try {
                    $this->save($request->request->all(), (int) $subject->userId);

                    return InstallerPage::redirect($this->router->generate(self::ROUTE));
                } catch (\InvalidArgumentException $invalid) {
                    $error = $this->text('error_' . $invalid->getMessage());
                } catch (Throwable) {
                    $error = $this->text('error_failed');
                }
            }
        }

        $notice = $this->session->get(self::FLASH);
        $this->session->remove(self::FLASH);
        $html = $this->views->render('extensions/admin_page.twig', [
            'title' => $this->text('title'),
            'nav' => AdminNavigation::items($this->router, $this->translator, CoreRoutes::ADMIN_EXTENSIONS),
            'body' => new SafeHtml($this->body(is_string($notice) ? $notice : null, $error)),
        ]);

        return new Response($html, $error === null ? 200 : 422, [
            'Content-Type' => 'text/html; charset=UTF-8', 'Cache-Control' => 'no-store, private',
        ]);
    }

    /** @param array<string, mixed> $input */
    private function save(array $input, int $userId): void
    {
        if (($input['remove'] ?? '') === '1') {
            $this->settings->clear();
            $this->audit->record($userId, 'nolviko.google.client_removed');
            $this->session->set(self::FLASH, $this->text('removed'));

            return;
        }

        $clientId = trim(is_string($input['client_id'] ?? null) ? $input['client_id'] : '');
        $secret = trim(is_string($input['client_secret'] ?? null) ? $input['client_secret'] : '');
        if (preg_match('/^[0-9A-Za-z._-]{1,200}\.apps\.googleusercontent\.com$/D', $clientId) !== 1) {
            throw new \InvalidArgumentException('client_id');
        }
        if ($secret === '' && !$this->settings->hasSecret()) {
            throw new \InvalidArgumentException('secret');
        }
        if ($secret !== '' && preg_match('/^[\x21-\x7E]{8,200}$/D', $secret) !== 1) {
            throw new \InvalidArgumentException('secret');
        }

        $this->settings->save($clientId, $secret === '' ? null : $secret);
        $this->audit->record($userId, 'nolviko.google.client_saved');
        $this->session->set(self::FLASH, $this->text('saved'));
    }

    private function body(?string $notice, ?string $error): string
    {
        $callback = $this->site->absolute($this->router->generate(CoreRoutes::AUTH_EXTERNAL_CALLBACK, [
            'provider' => 'google',
        ]));
        $ready = $this->settings->hasSecret();
        $fresh = $this->admin->isFresh();
        $locked = $this->settings->fromConfig();

        $html = ($notice === null ? '' : '<p role="status">' . $this->e($notice) . '</p>')
            . ($error === null ? '' : '<p role="alert">' . $this->e($error) . '</p>')
            . '<section class="panel panel-pad stack"><p><span class="chip '
            . ($ready ? 'chip-new' : 'chip-amber') . '">'
            . $this->e($this->text($ready ? 'status_on' : 'status_off')) . '</span> '
            . $this->e($this->text($ready ? 'status_on_help' : 'status_off_help')) . '</p></section>'
            . '<section class="panel panel-pad stack"><h2>' . $this->e($this->text('steps_title'))
            . '</h2><ol class="stack">'
            . '<li>' . $this->e($this->text('step_console')) . ' <a href="' . self::CONSOLE . '"'
            . ' rel="noopener noreferrer"'
            . ' target="_blank">console.cloud.google.com</a></li>'
            . '<li>' . $this->e($this->text('step_client')) . '</li>'
            . '<li>' . $this->e($this->text('step_redirect')) . '<br>'
            . ($callback === null ? '<strong>' . $this->e($this->text('no_site_url')) . '</strong>'
                : '<code>' . $this->e($callback) . '</code>') . '</li>'
            . '<li>' . $this->e($this->text('step_paste')) . '</li></ol></section>';

        if ($locked) {
            return $html . '<section class="panel panel-pad stack"><p>' . $this->e($this->text('from_config')) . '</p>'
                . '<p><code>' . $this->e($this->settings->clientId()) . '</code></p></section>';
        }

        $token = '<input type="hidden" name="' . $this->e(CsrfTokens::FIELD) . '" value="'
            . $this->e($this->csrf->token()) . '">';
        $disabled = $fresh ? '' : ' disabled';
        $html .= ($fresh ? '' : '<p>' . $this->e($this->text('reauth_hint')) . ' <a href="'
                . $this->e($this->router->generate(CoreRoutes::ADMIN_REAUTH)) . '">'
                . $this->e($this->translator->translate('admin.reauth.title')) . '</a></p>')
            . '<form method="post" action="' . $this->e($this->router->generate(self::ROUTE))
            . '" class="panel panel-pad stack">'
            . $token
            . '<p><label for="google-client-id">' . $this->e($this->text('client_id')) . '</label>'
            . '<input id="google-client-id" name="client_id" type="text" required maxlength="240" spellcheck="false"'
            . ' autocomplete="off" value="' . $this->e($this->settings->clientId()) . '"'
            . ' placeholder="1234567890-abc.apps.googleusercontent.com"></p>'
            . '<p><label for="google-client-secret">' . $this->e($this->text('client_secret')) . '</label>'
            . '<input id="google-client-secret" name="client_secret" type="password" maxlength="200" autocomplete="off"'
            . ($ready ? ' placeholder="' . $this->e($this->text('secret_kept')) . '"' : ' required') . '></p>'
            . '<p><button type="submit"' . $disabled . '>' . $this->e($this->text('save')) . '</button></p></form>';

        if ($ready) {
            $html .= '<form method="post" action="' . $this->e($this->router->generate(self::ROUTE)) . '">' . $token
                . '<input type="hidden" name="remove" value="1"><button class="btn-d" type="submit"' . $disabled . '>'
                . $this->e($this->text('remove')) . '</button></form>';
        }

        return $html;
    }

    private function text(string $key): string
    {
        return $this->translator->translate('nolviko.google.' . $key);
    }

    private function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
