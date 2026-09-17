<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Dotenv\Dotenv;
use Illuminate\Contracts\Console\Kernel;
use PragmaRX\Google2FA\Google2FA;

/*
|--------------------------------------------------------------------------
| Configuration
|--------------------------------------------------------------------------
*/

// App/Brand name and version are displayed.
define('APP_NAME', 'Artisan Console');
define('APP_VERSION', '1.0.0');

// true: only whitelisted commands; false: any Artisan command (not recommended).
define('SANDBOX_MODE', true);

$google2fa = new Google2FA();

$dotenv = Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->safeLoad();

$CONSOLE_SECRET = $_ENV['CONSOLE_SECRET'] ?? null;

$TOKEN_COOKIE = 'artisan_console_token';

$TOKEN_TTL = 12 * 60 * 60; // 12 hours

/*
|--------------------------------------------------------------------------
| Whitelist
|--------------------------------------------------------------------------
|
| Key   = command exposed to terminal
| Value = actual Artisan command
|
| Applied only when SANDBOX_MODE is true.
| Do NOT add commands that allow arbitrary code execution.
|
*/

$WHITELIST_COMMANDS = [
    'down' => 'down',
    'up' => 'up',

    'migrate' => 'migrate',
    'migrate --force' => 'migrate --force',
    'migrate:status' => 'migrate:status',

    'optimize' => 'optimize',

    'cache:clear' => 'cache:clear',
    'config:clear' => 'config:clear',
    'config:cache' => 'config:cache',

    'route:clear' => 'route:clear',
    'route:cache' => 'route:cache',

    'view:clear' => 'view:clear',
    'view:cache' => 'view:cache',

    'event:clear' => 'event:clear',
    'event:cache' => 'event:cache',

    // If truly necessary:
    // 'queue:restart' => 'queue:restart',
];

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function jsonResponse(array $data, int $status = 200): never
{
    http_response_code($status);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        $data,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

function tokenCookieOptions(int $expires): array
{
    return [
        'expires' => $expires,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Strict',
    ];
}

function createToken(string $secret, int $ttl): string
{
    $expires = time() + $ttl;

    $random = bin2hex(random_bytes(32));

    $payload = $expires . '.' . $random;

    $signature = hash_hmac(
        'sha256',
        $payload,
        $secret
    );

    return $payload . '.' . $signature;
}

function validateToken(
    ?string $token,
    string $secret
): array {
    if (!$token) {
        return [
            'valid' => false,
            'expires_at' => null,
            'remaining' => 0,
        ];
    }

    $parts = explode('.', $token);

    if (count($parts) !== 3) {
        return [
            'valid' => false,
            'expires_at' => null,
            'remaining' => 0,
        ];
    }

    [$expires, $random, $signature] = $parts;

    if (!ctype_digit($expires)) {
        return [
            'valid' => false,
            'expires_at' => null,
            'remaining' => 0,
        ];
    }

    $expires = (int) $expires;

    $payload = $expires . '.' . $random;

    $expected = hash_hmac(
        'sha256',
        $payload,
        $secret
    );

    if (!hash_equals($expected, $signature)) {
        return [
            'valid' => false,
            'expires_at' => null,
            'remaining' => 0,
        ];
    }

    $remaining = $expires - time();

    if ($remaining <= 0) {
        return [
            'valid' => false,
            'expires_at' => $expires,
            'remaining' => 0,
        ];
    }

    return [
        'valid' => true,
        'expires_at' => $expires,
        'remaining' => $remaining,
    ];
}

function formatRemaining(int $seconds): string
{
    if ($seconds <= 0) {
        return '--/--';
    }

    $days = intdiv($seconds, 86400);
    $seconds %= 86400;

    $hours = intdiv($seconds, 3600);
    $seconds %= 3600;

    $minutes = intdiv($seconds, 60);
    $seconds %= 60;

    $parts = [];

    if ($days > 0) {
        $parts[] = str_pad((string) $days, 2, '0', STR_PAD_LEFT);
    }

    if ($hours > 0 || $days > 0) {
        $parts[] = str_pad((string) $hours, 2, '0', STR_PAD_LEFT);
    }

    if ($minutes > 0 || $hours > 0 || $days > 0) {
        $parts[] = str_pad((string) $minutes, 2, '0', STR_PAD_LEFT);
    }

    $parts[] = str_pad((string) $seconds, 2, '0', STR_PAD_LEFT);

    return implode(':', $parts);
}

/*
|--------------------------------------------------------------------------
| Basic method handling
|--------------------------------------------------------------------------
*/

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {

    /*
     * GET = render terminal.
     * The HTML is below.
     */

} else {

    /*
    |--------------------------------------------------------------------------
    | API request
    |--------------------------------------------------------------------------
    */

    $input = json_decode(
        file_get_contents('php://input'),
        true
    );

    $command = trim((string) ($input['command'] ?? ''));

    if ($command === '') {
        jsonResponse([
            'success' => false,
            'output' => 'Empty command.',
        ], 400);
    }

    /*
    |--------------------------------------------------------------------------
    | Current token status
    |--------------------------------------------------------------------------
    */

    $token = $_COOKIE[$TOKEN_COOKIE] ?? null;

    $auth = validateToken(
        $token,
        (string) $CONSOLE_SECRET
    );

    /*
    |--------------------------------------------------------------------------
    | AUTH
    |--------------------------------------------------------------------------
    */

    if (preg_match('/^auth\s+(.+)$/s', $command, $matches)) {

        $verifyCode = trim($matches[1]);

        if (!$CONSOLE_SECRET) {
            jsonResponse([
                'success' => false,
                'output' => "CONSOLE_SECRET is not configured on server.",
            ], 500);
        }

        if (!$google2fa->verifyKey($CONSOLE_SECRET, $verifyCode, 0)) {
            jsonResponse([
                'success' => false,
                'output' => "Incorrect verification code.",
                'auth' => [
                    'authenticated' => false,
                    'remaining' => 0,
                    'remaining_formatted' => 'expired',
                ],
            ], 403);
        }

        $token = createToken(
            (string) $CONSOLE_SECRET,
            $TOKEN_TTL
        );

        $expiresAt = time() + $TOKEN_TTL;

        setcookie(
            $TOKEN_COOKIE,
            $token,
            tokenCookieOptions($expiresAt)
        );

        jsonResponse([
            'success' => true,
            'output' =>
                "Authentication successful.\r\n" .
                "Token expires in " .
                formatRemaining($TOKEN_TTL) .
                ".",

            'auth' => [
                'authenticated' => true,
                'expires_at' => $expiresAt,
                'remaining' => $TOKEN_TTL,
                'remaining_formatted' =>
                    formatRemaining($TOKEN_TTL),
            ],
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | LOGOUT
    |--------------------------------------------------------------------------
    */

    if ($command === 'logout') {
        setcookie(
            $TOKEN_COOKIE,
            '',
            tokenCookieOptions(time() - 3600)
        );

        jsonResponse([
            'success' => true,
            'output' => 'Logged out.',
            'auth' => [
                'authenticated' => false,
                'remaining' => 0,
                'remaining_formatted' => 'expired',
            ],
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | STATUS
    |--------------------------------------------------------------------------
    */

    if ($command === 'status') {

        if (!$auth['valid']) {
            jsonResponse([
                'success' => true,
                'output' => "Not authenticated.",
                'auth' => [
                    'authenticated' => false,
                    'expires_at' => $auth['expires_at'],
                    'remaining' => 0,
                    'remaining_formatted' => 'expired',
                ],
            ]);
        }

        jsonResponse([
            'success' => true,
            'output' =>
                "Authenticated.\r\n" .
                "Token expires in " .
                formatRemaining($auth['remaining']) .
                ".",

            'auth' => [
                'authenticated' => true,
                'expires_at' => $auth['expires_at'],
                'remaining' => $auth['remaining'],
                'remaining_formatted' =>
                    formatRemaining($auth['remaining']),
            ],
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | Require authentication
    |--------------------------------------------------------------------------
    */

    if (!$auth['valid']) {

        jsonResponse([
            'success' => false,
            'output' =>
                "Authentication required.\r\n" .
                "Use: auth <Verification code>",

            'auth' => [
                'authenticated' => false,
                'expires_at' => $auth['expires_at'],
                'remaining' => 0,
                'remaining_formatted' => 'expired',
            ],
        ], 401);
    }

    /*
    |--------------------------------------------------------------------------
    | Enforce sandbox command restrictions
    |--------------------------------------------------------------------------
    |
    | IMPORTANT:
    | When SANDBOX_MODE is enabled, compare the complete input against the whitelist.
    | Otherwise, pass the input directly to Artisan, including arguments/options.
    |
    | Therefore:
    |
    |   optimize
    |
    | is allowed, but:
    |
    |   optimize something
    |
    | is NOT.
    |
    */

    if (
        SANDBOX_MODE && !array_key_exists(
            $command,
            $WHITELIST_COMMANDS
        )
    ) {

        jsonResponse([
            'success' => false,
            'output' => "Command not allowed: {$command}",
            'auth' => [
                'authenticated' => true,
                'expires_at' => $auth['expires_at'],
                'remaining' => $auth['remaining'],
                'remaining_formatted' =>
                    formatRemaining($auth['remaining']),
            ],
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | Boot Laravel
    |--------------------------------------------------------------------------
    */

    try {
        $app = require_once __DIR__ . '/../bootstrap/app.php';

        /** @var Kernel $kernel */
        $kernel = $app->make(Kernel::class);
        /*
        |--------------------------------------------------------------------------
        | Run the resolved Artisan command
        |--------------------------------------------------------------------------
        */
        $artisanCommand = SANDBOX_MODE
            ? $WHITELIST_COMMANDS[$command]
            : $command;
        $status = $kernel->call($artisanCommand);
        $output = $kernel->output();

        /*
        |--------------------------------------------------------------------------
        | Return command result
        |--------------------------------------------------------------------------
        */

        jsonResponse([
            'success' => $status === 0,
            'exit_code' => $status,
            'output' => $output,
            'auth' => [
                'authenticated' => true,
                'expires_at' => $auth['expires_at'],
                'remaining' => $auth['remaining'],
                'remaining_formatted' =>
                    formatRemaining($auth['remaining']),
            ],
        ], $status === 0 ? 200 : 500);
    } catch (Throwable $e) {
        /*
        |--------------------------------------------------------------------------
        | Do not expose stack traces
        |--------------------------------------------------------------------------
        */
        jsonResponse([
            'success' => false,
            'output' =>
                'Command execution failed: ' .
                $e->getMessage(),
            'auth' => [
                'authenticated' => true,
                'expires_at' => $auth['expires_at'],
                'remaining' => $auth['remaining'],
                'remaining_formatted' =>
                    formatRemaining($auth['remaining']),
            ],
        ], 500);
    }
    exit;
}

$WHITELIST_JSON = json_encode(
    array_keys($WHITELIST_COMMANDS),
    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= APP_NAME ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link
        href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap"
        rel="stylesheet">

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css">
    <script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js"></script>

    <script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js"></script>
    <style>
        :root {
            --bg: #0a0c11;
            --surface: #12151c;
            --surface-2: #181c25;
            --border: #262b36;
            --text: #e6e9ef;
            --text-muted: #838ba0;
            --accent: #4fd1c5;
            --accent-dim: #245852;
            --ok: #34d399;
            --danger: #f87171;
            --warn: #fbbf24;
            --font-mono: 'IBM Plex Mono', ui-monospace, 'SF Mono', monospace;
            --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
            --radius: 8px;
            --term-bg: #0d1017;
        }

        html[data-theme="light"] {
            --bg: #f3f4f7;
            --surface: #ffffff;
            --surface-2: #eceef2;
            --border: #dde0e7;
            --text: #171a21;
            --text-muted: #656d7e;
            --accent: #0f9c8e;
            --accent-dim: #cdf0ea;
            --ok: #0a9463;
            --danger: #dc4646;
            --warn: #b3790c;
            --term-bg: #ffffff;
        }

        * {
            box-sizing: border-box;
        }

        html,
        body {
            width: 100%;
            height: 100%;
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family: var(--font-sans);
            overflow: hidden;
        }

        .app {
            display: flex;
            flex-direction: column;
            height: 100%;
        }

        /* ---------- Header ---------- */
        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 20px;
            border-bottom: 1px solid var(--border);
            background: var(--surface);
            flex-shrink: 0;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .brand-mark {
            width: 10px;
            height: 10px;
            border-radius: 2px;
            background: var(--accent);
            box-shadow: 0 0 10px var(--accent);
        }

        .brand-name {
            font-family: var(--font-mono);
            font-weight: 600;
            font-size: 14px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .brand-sub {
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--text-muted);
            letter-spacing: 0.04em;
        }

        .theme-toggle {
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--surface-2);
            border: 1px solid var(--border);
            border-radius: 999px;
            padding: 5px 12px;
            cursor: pointer;
            color: var(--text-muted);
            font-family: var(--font-mono);
            font-size: 11px;
            letter-spacing: 0.04em;
            transition: color 0.15s, border-color 0.15s;
        }

        .theme-toggle:hover {
            color: var(--text);
            border-color: var(--accent);
        }

        .theme-toggle svg {
            width: 14px;
            height: 14px;
            display: block;
        }

        /* ---------- Layout ---------- */
        .layout {
            display: grid;
            grid-template-columns: 300px 1fr;
            flex: 1;
            min-height: 0;
        }

        .sidebar {
            border-right: 1px solid var(--border);
            background: var(--surface);
            padding: 16px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .panel {
            background: var(--surface-2);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 14px;
        }

        .panel-title {
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--text-muted);
            margin: 0 0 12px 0;
        }

        /* ---------- Session panel (signature element) ---------- */
        .session-status {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 12px;
        }

        .led {
            width: 9px;
            height: 9px;
            border-radius: 50%;
            background: var(--danger);
            flex-shrink: 0;
            transition: background 0.2s;
        }

        .led.on {
            background: var(--ok);
            box-shadow: 0 0 8px var(--ok);
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {

            0%,
            100% {
                opacity: 1;
            }

            50% {
                opacity: 0.45;
            }
        }

        .session-label {
            font-family: var(--font-mono);
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.05em;
        }

        .session-label.on {
            color: var(--ok);
        }

        .session-label.off {
            color: var(--danger);
        }

        .countdown {
            font-family: var(--font-mono);
            font-size: 30px;
            font-weight: 600;
            letter-spacing: 0.03em;
            font-variant-numeric: tabular-nums;
            color: var(--text);
            line-height: 1;
            margin-bottom: 10px;
        }

        .countdown.dim {
            color: var(--text-muted);
        }

        .ttl-track {
            height: 4px;
            border-radius: 2px;
            background: var(--border);
            overflow: hidden;
        }

        .ttl-fill {
            height: 100%;
            width: 100%;
            background: var(--accent);
            transition: width 1s linear, background 0.3s;
            transform-origin: left;
        }

        .ttl-fill.warn {
            background: var(--warn);
        }

        .ttl-fill.danger {
            background: var(--danger);
        }

        /* ---------- Auth form ---------- */
        .field-label {
            display: block;
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }

        .field-row {
            display: flex;
            gap: 8px;
        }

        input[type="password"],
        input[type="text"] {
            flex: 1;
            min-width: 0;
            background: var(--bg);
            border: 1px solid var(--border);
            color: var(--text);
            font-family: var(--font-mono);
            font-size: 13px;
            padding: 8px 10px;
            border-radius: 6px;
            outline: none;
            transition: border-color 0.15s;
        }

        input[type="password"]:focus,
        input[type="text"]:focus {
            border-color: var(--accent);
        }

        button {
            font-family: var(--font-sans);
            font-size: 12px;
            font-weight: 600;
            border-radius: 6px;
            border: 1px solid var(--border);
            padding: 8px 14px;
            cursor: pointer;
            transition: border-color 0.15s, background 0.15s, opacity 0.15s;
            background: var(--surface);
            color: var(--text);
        }

        button:hover:not(:disabled) {
            border-color: var(--accent);
        }

        button:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }

        .btn-primary {
            background: var(--accent);
            border-color: var(--accent);
            color: #06231f;
        }

        .btn-primary:hover:not(:disabled) {
            opacity: 0.88;
            border-color: var(--accent);
        }

        .btn-danger-outline {
            border-color: var(--danger);
            color: var(--danger);
            background: transparent;
            width: 100%;
        }

        .btn-danger-outline:hover:not(:disabled) {
            background: var(--danger);
            color: #fff;
        }

        .btn-block {
            width: 100%;
        }

        .hint {
            font-family: var(--font-mono);
            font-size: 10.5px;
            color: var(--text-muted);
            margin-top: 8px;
            line-height: 1.5;
        }

        /* ---------- Command chips ---------- */
        .chip-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }

        .chip {
            font-family: var(--font-mono);
            font-size: 11px;
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 6px 9px;
            border-radius: 5px;
            cursor: pointer;
            transition: border-color 0.15s, color 0.15s;
        }

        .chip:hover:not(:disabled) {
            border-color: var(--accent);
            color: var(--accent);
        }

        .chip:disabled {
            opacity: 0.35;
            cursor: not-allowed;
        }

        .hidden {
            display: none !important;
        }

        /* ---------- Terminal ---------- */
        .term-wrap {
            display: flex;
            flex-direction: column;
            min-width: 0;
            min-height: 0;
        }

        .term-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 8px 16px;
            border-bottom: 1px solid var(--border);
            background: var(--surface);
            flex-shrink: 0;
        }

        .term-bar-title {
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--text-muted);
            letter-spacing: 0.04em;
        }

        .term-clear {
            font-family: var(--font-mono);
            font-size: 11px;
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 4px 10px;
        }

        #terminal {
            flex: 1;
            min-height: 0;
            background: var(--term-bg);
            padding: 8px 4px 0 8px;
        }

        @media (max-width: 760px) {
            .layout {
                grid-template-columns: 1fr;
                grid-template-rows: auto 1fr;
            }

            .sidebar {
                border-right: none;
                border-bottom: 1px solid var(--border);
                flex-direction: row;
                flex-wrap: wrap;
                max-height: 40vh;
            }

            .panel {
                flex: 1 1 260px;
            }
        }

        .sidebar::-webkit-scrollbar,
        .xterm-viewport::-webkit-scrollbar {
            display: none;
        }

        .sidebar,
        .xterm-viewport {
            -ms-overflow-style: none;
            scrollbar-width: none;
        }
    </style>
</head>

<body>
    <div class="app">

        <header class="topbar">
            <div class="brand">
                <span class="brand-mark"></span>
                <div>
                    <div class="brand-name"><?= APP_NAME ?></div>
                    <div class="brand-sub">Version <?= APP_VERSION ?></div>
                </div>
            </div>
            <button class="theme-toggle" id="themeToggle" type="button">
                <svg id="themeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="4"></circle>
                    <path
                        d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4">
                    </path>
                </svg>
                <span id="themeLabel">Dark</span>
            </button>
        </header>

        <div class="layout">
            <aside class="sidebar">

                <div class="panel">
                    <p class="panel-title">Session</p>
                    <div class="session-status">
                        <span class="led" id="ledDot"></span>
                        <span class="session-label off" id="sessionLabel">Not authenticated</span>
                    </div>
                    <div class="countdown dim" id="countdown">--:--</div>
                    <div class="ttl-track">
                        <div class="ttl-fill" id="ttlFill" style="width:0%"></div>
                    </div>
                </div>

                <div class="panel" id="authPanel">
                    <p class="panel-title">Authenticate</p>
                    <!-- <label class="field-label" for="totpInput">Verification code</label> -->
                    <div class="field-row">
                        <input type="text" id="totpInput" placeholder="Verification code" autocomplete="off">
                        <button class="btn-primary" id="authBtn" type="button">Auth</button>
                    </div>
                    <p class="hint">Or type <code>auth &lt;Verification code&gt;</code> in the console.</p>
                </div>

                <div class="panel hidden" id="logoutPanel">
                    <button class="btn-danger-outline" id="logoutBtn" type="button">Log out</button>
                </div>

                <div class="panel">
                    <p class="panel-title"><?= SANDBOX_MODE ? 'Available commands' : 'Quick commands'; ?></p>
                    <?php if (!SANDBOX_MODE): ?>
                        <p class="hint">Use <code>list</code> to see all commands.</p>
                    <?php endif; ?>
                    <div class="chip-list" id="chipList"></div>
                </div>

            </aside>

            <div class="term-wrap">
                <div class="term-bar">
                    <span class="term-bar-title">console</span>
                    <button class="term-clear" id="clearBtn" type="button">clear</button>
                </div>
                <div id="terminal"></div>
            </div>
        </div>

    </div>

    <script>
        (function () {
            const WHITELIST_COMMANDS = <?= $WHITELIST_JSON; ?>;
            const THEME_KEY = 'artisan-console-theme';

            /* ------------------------------------------------------------------ */
            /* Theme                                                              */
            /* ------------------------------------------------------------------ */
            const root = document.documentElement;
            const themeToggle = document.getElementById('themeToggle');
            const themeLabel = document.getElementById('themeLabel');
            let terminal = null;

            function applyTheme(theme) {
                root.setAttribute('data-theme', theme);
                themeLabel.textContent = theme === 'light' ? 'Light' : 'Dark';
                if (terminal) {
                    terminal.options.theme = xtermTheme(theme);
                }
            }

            function xtermTheme(theme) {
                return theme === 'light'
                    ? {
                        background: '#ffffff',
                        foreground: '#171a21',
                        cursor: '#0f9c8e',
                        selectionBackground: '#4fd1c5'
                    }
                    : {
                        background: '#0d1017',
                        foreground: '#e6e9ef',
                        cursor: '#4fd1c5',
                        selectionBackground: '#0f9c8e'
                    };
            }

            let savedTheme = 'dark';
            try {
                savedTheme = localStorage.getItem(THEME_KEY) || 'dark';
            } catch (e) { /* localStorage unavailable */ }
            applyTheme(savedTheme);

            themeToggle.addEventListener('click', function () {
                const next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
                applyTheme(next);
                try { localStorage.setItem(THEME_KEY, next); } catch (e) { }
            });

            /* ------------------------------------------------------------------ */
            /* Terminal                                                           */
            /* ------------------------------------------------------------------ */
            terminal = new Terminal({
                cursorBlink: true,
                fontSize: 14,
                fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
                theme: xtermTheme(savedTheme)
            });
            const fitAddon = new FitAddon.FitAddon();
            terminal.loadAddon(fitAddon);
            terminal.open(document.getElementById('terminal'));
            fitAddon.fit();
            window.addEventListener('resize', function () { fitAddon.fit(); });

            const C_OK = '\x1b[32m';
            const C_ERR = '\x1b[31m';
            const C_DIM = '\x1b[90m';
            const C_ACCENT = '\x1b[36m';
            const C_RESET = '\x1b[0m';

            function writeLine(text) { terminal.write((text || '') + '\r\n'); }

            terminal.write(C_ACCENT + '<?= APP_NAME ?>' + C_RESET + ' — v<?= APP_VERSION ?>\r\n\r\n');
            terminal.write('$ ');

            let commandBuffer = '';
            let busy = false;

            /* ------------------------------------------------------------------ */
            /* Auth state / session panel                                         */
            /* ------------------------------------------------------------------ */
            const ledDot = document.getElementById('ledDot');
            const sessionLabel = document.getElementById('sessionLabel');
            const countdownEl = document.getElementById('countdown');
            const ttlFill = document.getElementById('ttlFill');
            const authPanel = document.getElementById('authPanel');
            const logoutPanel = document.getElementById('logoutPanel');
            const totpInput = document.getElementById('totpInput');
            const authBtn = document.getElementById('authBtn');
            const logoutBtn = document.getElementById('logoutBtn');
            const clearBtn = document.getElementById('clearBtn');
            const chipList = document.getElementById('chipList');

            let remaining = 0;
            let ttlTotal = 30 * 60;
            let tickHandle = null;

            WHITELIST_COMMANDS.forEach(function (cmd) {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'chip';
                btn.textContent = cmd;
                btn.disabled = true;
                btn.addEventListener('click', function () {
                    if (busy || btn.disabled) return;
                    if (commandBuffer.length > 0) {
                        commandBuffer = '';
                        terminal.write('\r\n' + '$ ')
                    }
                    runCommand(cmd);
                });
                chipList.appendChild(btn);
            });

            function formatRemaining(seconds) {
                if (seconds <= 0) return '--/--';
                const days = Math.floor(seconds / 86400);
                seconds %= 86400;
                const hours = Math.floor(seconds / 3600);
                seconds %= 3600;
                const minutes = Math.floor(seconds / 60);
                seconds %= 60;
                const parts = [];
                if (days > 0) parts.push(String(days).padStart(2, '0'));
                if (hours > 0 || days > 0) parts.push(String(hours).padStart(2, '0'));
                if (minutes > 0 || hours > 0 || days > 0) parts.push(String(minutes).padStart(2, '0'));
                parts.push(String(seconds).padStart(2, '0'));
                return parts.join(':');
            }

            function stopTicking() {
                if (tickHandle) { clearInterval(tickHandle); tickHandle = null; }
            }

            function startTicking() {
                stopTicking();
                tickHandle = setInterval(function () {
                    remaining -= 1;
                    if (remaining <= 0) {
                        remaining = 0;
                        stopTicking();
                        updateAuthUI({ authenticated: false, remaining: 0, remaining_formatted: 'expired' });
                        writeLine('');
                        writeLine(C_ERR + '[session] token expired' + C_RESET);
                        terminal.write('$ ');
                        return;
                    }
                    renderCountdown();
                }, 1000);
            }

            function renderCountdown() {
                countdownEl.textContent = formatRemaining(remaining);
                countdownEl.classList.toggle('dim', remaining <= 0);
                const pct = ttlTotal > 0 ? Math.max(0, Math.min(100, (remaining / ttlTotal) * 100)) : 0;
                ttlFill.style.width = pct + '%';
                ttlFill.classList.toggle('warn', pct <= 33 && pct > 10);
                ttlFill.classList.toggle('danger', pct <= 10);
            }

            function updateAuthUI(auth) {
                if (!auth) return;
                const authed = !!auth.authenticated;

                ledDot.classList.toggle('on', authed);
                sessionLabel.textContent = authed ? 'Token lifetime' : 'Not authenticated';
                sessionLabel.classList.toggle('on', authed);
                sessionLabel.classList.toggle('off', !authed);

                authPanel.classList.toggle('hidden', authed);
                logoutPanel.classList.toggle('hidden', !authed);

                chipList.querySelectorAll('.chip').forEach(function (btn) {
                    btn.disabled = !authed;
                });

                if (authed) {
                    remaining = typeof auth.remaining === 'number' ? auth.remaining : 0;
                    ttlTotal = Math.max(ttlTotal, remaining);
                    renderCountdown();
                    startTicking();
                } else {
                    remaining = 0;
                    stopTicking();
                    countdownEl.textContent = '——/——';
                    countdownEl.classList.add('dim');
                    ttlFill.style.width = '0%';
                    ttlFill.classList.remove('warn', 'danger');
                }
            }

            /* ------------------------------------------------------------------ */
            /* Command execution                                                   */
            /* ------------------------------------------------------------------ */
            async function runCommand(cmd, silent = false) {
                if (busy) {
                    if (!silent) writeLine(C_DIM + 'Command is still running…' + C_RESET);
                    return;
                }
                busy = true;

                if (!silent) {
                    writeLine(C_ACCENT + C_RESET + cmd);
                }

                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        },
                        body: JSON.stringify({ command: cmd })
                    });
                    const data = await response.json();

                    if (data.output) {
                        const color = data.success ? '' : C_ERR;
                        terminal.write(color + data.output.replace(/\n/g, '\r\n') + (color ? C_RESET : '') + '\r\n');
                    }

                    if (data.auth) {
                        updateAuthUI(data.auth);
                    }
                } catch (error) {
                    writeLine(C_ERR + 'Request failed: ' + error.message + C_RESET);
                } finally {
                    busy = false;
                    if (!silent) terminal.write('$ ');
                }
            }

            /* Silent sync on load — reflects an existing HttpOnly cookie/token. */
            runCommand('status', true).then(function () {
                terminal.write('$ ');
            });

            /* ------------------------------------------------------------------ */
            /* Sidebar controls                                                    */
            /* ------------------------------------------------------------------ */
            authBtn.addEventListener('click', function () { doAuth(); });
            totpInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') doAuth();
            });

            function doAuth() {
                const totp = totpInput.value.trim();
                if (!totp || busy) return;
                totpInput.value = '';
                runCommand('auth ' + totp);
            }

            logoutBtn.addEventListener('click', function () {
                if (busy) return;
                runCommand('logout');
            });

            clearBtn.addEventListener('click', function () {
                terminal.clear();
            });

            /* ------------------------------------------------------------------ */
            /* Terminal keystrokes (typed commands still work)                    */
            /* ------------------------------------------------------------------ */
            terminal.onData(function (data) {
                if (busy) return;

                if (data === '\r') {
                    terminal.write('\r\n');
                    const input = commandBuffer.trim();
                    commandBuffer = '';
                    if (input !== '') {
                        runCommand(input, true).then(function () {
                            terminal.write('$ ');
                        });
                    } else {
                        terminal.write('$ ');
                    }
                    return;
                }

                if (data === '\u007F') {
                    if (commandBuffer.length > 0) {
                        commandBuffer = commandBuffer.slice(0, -1);
                        terminal.write('\b \b');
                    }
                    return;
                }

                if (data === '\u0003') {
                    terminal.write('^C\r\n$ ');
                    commandBuffer = '';
                    return;
                }

                // Accepts both typed and pasted input.
                if (data.length > 0) {
                    const text = data.replace(/\r?\n/g, '');
                    commandBuffer += text;
                    terminal.write(text);
                }
            });
        })();
    </script>
</body>

</html>
