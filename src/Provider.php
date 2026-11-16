<?php

declare(strict_types=1);

/*
 * Nolviko "Sign in with Google" extension (2026-11-15, PLG-03, Google only for now). Core runs the flow (state,
 * PKCE, account lookup, sign-up, linking, bans, second step); this extension talks to Google and has a settings
 * page where the site owner enters the Google client (owner decision: no file editing needed).
 */

use Doctrine\DBAL\Connection;
use Nolviko\Core\Application\CompositionRoot;
use Nolviko\Core\Config\Config;
use Nolviko\Core\Extensions\ExtensionContext;
use Nolviko\Core\Extensions\ExtensionProvider;
use Nolviko\Core\Http\ErrorResponder;
use Nolviko\Core\Locale\MessageTranslator;
use Nolviko\Core\Routing\RouteDefinition;
use Nolviko\Core\Routing\Router;
use Nolviko\Core\Session\CsrfTokens;
use Nolviko\Core\Session\Session;
use Nolviko\Core\View\TemplateRenderer;
use Nolviko\Modules\Admin\Http\AdminSession;
use Nolviko\Modules\Admin\Infrastructure\DbalAdminAudit;
use Nolviko\Modules\Permissions\Domain\PermissionDefinition;
use Nolviko\Modules\Permissions\Domain\PermissionType;
use Nolviko\Modules\Seo\Domain\SiteUrl;
use Nolviko\Modules\Users\Http\RequestSubject;
use NolvikoExt\Google\AdminHandler;
use NolvikoExt\Google\GoogleProvider;
use NolvikoExt\Google\GoogleSettings;

require_once __DIR__ . '/GoogleSettings.php';
require_once __DIR__ . '/GoogleProvider.php';
require_once __DIR__ . '/AdminHandler.php';

return new class implements ExtensionProvider {
    public function register(ExtensionContext $context): void
    {
        $directory = $context->storage();
        $context->service(
            'nolviko.google.settings',
            static fn(?Config $config): GoogleSettings => new GoogleSettings($directory, $config),
            [CompositionRoot::CONFIG],
        );
        $context->service(
            'nolviko.google.identity',
            static fn(GoogleSettings $settings): GoogleProvider => new GoogleProvider($settings),
            ['nolviko.google.settings'],
        );
        $context->identityProvider('nolviko.google.identity');

        // Administrators only (checked in the handler); the permission lets the route exist for every group.
        $context->permission(new PermissionDefinition('nolviko.google.manage', PermissionType::Bool, default: true));
        $context->route(
            new RouteDefinition(
                AdminHandler::ROUTE,
                '/extensions/nolviko/google/admin',
                ['GET', 'POST'],
                requiresHttps: true,
            ),
            'nolviko.google.manage',
            static fn(
                MessageTranslator $translator,
                TemplateRenderer $views,
                RequestSubject $subjects,
                AdminSession $admin,
                CsrfTokens $csrf,
                Router $router,
                Session $session,
                Connection $db,
                ErrorResponder $errors,
                SiteUrl $site,
                GoogleSettings $settings,
            ): AdminHandler => new AdminHandler(
                $translator,
                $views,
                $subjects,
                $admin,
                $csrf,
                $router,
                $session,
                new DbalAdminAudit($db),
                $errors,
                $site,
                $settings,
            ),
            [
                MessageTranslator::class, TemplateRenderer::class, RequestSubject::class, AdminSession::class,
                CsrfTokens::class, Router::class, Session::class, Connection::class, ErrorResponder::class,
                SiteUrl::class, 'nolviko.google.settings',
            ],
        );
        $context->adminPage(AdminHandler::ROUTE);
    }
};
