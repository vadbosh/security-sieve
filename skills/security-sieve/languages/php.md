<!-- SPDX-License-Identifier: Apache-2.0 -->
# PHP Security Patterns

Targets PHP 8.x (Laravel, Symfony, plain PHP). Version notes are marked where behaviour changed. Further reading, not copied here: [OWASP PHP Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html),
[PHP manual: Security](https://www.php.net/manual/en/security.php), [Symfony security](https://symfony.com/doc/current/security.html).

## Framework Detection

| Indicator | Framework |
|-----------|-----------|
| `artisan`, `Illuminate\`, `*.blade.php`, `routes/web.php` | Laravel |
| `symfony.lock`, `Symfony\Component`, `*.html.twig`, `config/packages` | Symfony |
| `Doctrine\ORM`, `EntityManager`, `createQuery(` | Doctrine |
| `$_GET`, `$_POST`, `mysqli_*`, no `composer.json` | Plain PHP |

Attacker input: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `php://input`, `$_SERVER['HTTP_*']`,
`REQUEST_URI`, `PHP_SELF`, `$request->input()` / `all()` / `query`. Server-side: `config()`, `$_ENV`, `getenv()`.

## Safe Patterns (Do Not Flag)

```php
// SAFE: deployment configuration is not attacker input
Http::get(config('services.billing.url') . '/v1/invoices');   // NOT SSRF
file_get_contents(storage_path('app/report.csv'));            // NOT traversal
include __DIR__ . '/partials/header.php';                     // constant path, NOT LFI

// SAFE: prepared statements and bound values
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');
$stmt->execute(['email' => $email]);
User::where('email', $email)->first();
DB::select('SELECT * FROM users WHERE id = ?', [$id]);
User::whereRaw('lower(email) = ?', [strtolower($email)]);     // bindings passed
$em->createQuery('SELECT u FROM App\Entity\User u WHERE u.email = :e')->setParameter('e', $email);

// SAFE: auto-escaped output
{{ $name }}                      {{-- Blade runs htmlspecialchars --}}
{{ user.name }}                  {# Twig, HTML autoescape on in a stock setup #}
echo htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
```

## SQL Injection

CWE-89 | OWASP A05:2025 Injection

Placeholders protect values only. Identifiers (table, column, `ORDER BY` direction) need an allow-list.

```php
// VULNERABLE: concatenation
$pdo->query("SELECT * FROM users WHERE name = '" . $_GET['name'] . "'");
$mysqli->query("DELETE FROM posts WHERE id = $id");           // $id uncast request data
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = '$name'");   // string already built

// SAFE
$stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?');
$stmt->execute([$_GET['name']]);
```

### Eloquent / Laravel

```php
// VULNERABLE: raw fragments with request data
User::whereRaw("name = '$name'")->get();
User::orderByRaw($request->query('sort'))->get();
User::selectRaw("count(*) as c, $col")->get();
User::groupByRaw($request->input('g'))->get();   User::havingRaw("sum(x) > $min")->get();
DB::raw("COALESCE(a, '$default')");   DB::select("SELECT * FROM users WHERE id = $id");
User::where($request->input('column'), $value);               // column name from request
User::orderBy($request->input('sort'));

// SAFE
User::whereRaw('name = ?', [$name])->get();
User::orderBy(in_array($s, ['name', 'created_at'], true) ? $s : 'created_at');
User::whereIn('id', $ids);
```

A user-controlled column or operator in `where($column, $op, $value)` injects even though `$value` is
bound. JSON path keys (`->where('meta->' . $key, ...)`) also build SQL text.

### Doctrine DQL / QueryBuilder

```php
// VULNERABLE
$em->createQuery("SELECT u FROM App\Entity\User u WHERE u.name = '$name'");
$qb->where("u.name = '" . $name . "'");
$qb->andWhere($qb->expr()->eq('u.id', $id));                  // expr builds text, $id not bound
$conn->executeQuery("SELECT * FROM users WHERE id = $id");

// SAFE
$qb->where('u.name = :n')->setParameter('n', $name);
```

## Command Injection

CWE-78 | OWASP A05:2025 Injection

Sinks: `exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`, backticks, `pcntl_exec`,
`mail()` 5th parameter, Symfony `Process::fromShellCommandline`.

```php
// VULNERABLE
exec('convert ' . $_GET['file'] . ' out.png');
system("ping -c 1 $host");
$out = `grep $term /var/log/app.log`;
mail($to, $subj, $body, '', "-f$from");                       // sendmail option injection

// SAFE: argv array, no shell (array form of proc_open needs PHP 7.4+, unverified)
proc_open(['convert', $file, 'out.png'], $spec, $pipes);
$p = new Process(['convert', $file, 'out.png']);              // Symfony Process, argv form
```

`escapeshellarg` vs `escapeshellcmd`:
- `escapeshellarg($s)` quotes one argument. It does not stop the value being read as an option: a
  value like `--output=/tmp/x` is still a flag. Put `--` before it or allow-list the value.
- `escapeshellcmd($s)` escapes metacharacters of a whole command line but still lets an attacker add
  arguments. It does not make user input safe in a command line.
- Applying both to the same string can undo quoting and reopen injection. One layer per argument.

## Code Execution

CWE-94, CWE-95 | OWASP A05:2025 Injection

```php
// Always flag with non-literal input
eval($code);
assert($userString);              // string evaluation was removed in PHP 8.0; still runs on 7.x
preg_replace('/x/e', $r, $s);     // /e modifier is an error on current PHP; legacy code only
create_function('$a', $body);     // removed in PHP 8.0
$fn = $_GET['f']; $fn($_GET['a']);                            // variable function
call_user_func($_GET['cb'], $arg);   call_user_func_array([$obj, $_GET['m']], $args);
$class = $_GET['c']; new $class();                            // gadget instantiation, autoload effects

// SAFE: callable chosen from an allow-list
$handlers = ['csv' => 'exportCsv', 'json' => 'exportJson'];
$h = $handlers[$_GET['fmt']] ?? null;
if ($h === null) { abort(400); }
$h($data);
```

`is_callable()` is not a safety check: `'system'` is callable. Verified in the PHP 8.0 migration guide:
`assert()` no longer evaluates strings, and `create_function()` is removed.

Template injection (SSTI): `Twig\Environment::createTemplate($userString)`, `Blade::render($userString)`,
`$twig->render($_GET['tpl'])`, Smarty `fetch('string:' . $input)`. Flag when template source or name is
attacker-controlled.

## Deserialization

CWE-502 | OWASP A08:2025 Software or Data Integrity Failures

```php
// VULNERABLE
$data = unserialize($_COOKIE['prefs']);
$obj  = unserialize(base64_decode($request->input('state')));

// BETTER: no object instantiation
$data = unserialize($raw, ['allowed_classes' => false]);
// BEST: a format that cannot carry objects
$data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
```

- The PHP manual warns not to pass untrusted input to `unserialize()` even with `allowed_classes`.
  An allow-list narrows gadget reach, but allowed classes still run `__wakeup`, `__unserialize`,
  `__destruct`.
- If serialized data must round-trip through the client, sign it: `hash_hmac` plus `hash_equals`
  before `unserialize`.

### phar:// metadata

Before PHP 8.0, file functions (`file_exists`, `is_dir`, `filesize`, `getimagesize`, `copy`, ...) given
a `phar://` path unserialized the archive metadata, so an uploaded polyglot file plus a user-influenced
path gave object injection. PHP 8.0 stopped unserializing phar metadata automatically (verified in the
7.4 to 8.0 migration guide: "Metadata associated with a phar will no longer be automatically
unserialized"). Remaining risk on 8.x: explicit `Phar::getMetadata()` calls and `include` of a
`phar://` path, which runs the stub. On code that supports PHP < 8.0, flag user-controlled strings
reaching file functions without a scheme check.

## File Inclusion and Path Traversal

CWE-98, CWE-22 | OWASP A05:2025 Injection, A01:2025 Broken Access Control

```php
// VULNERABLE
include $_GET['page'] . '.php';
require $request->input('lang') . '/messages.php';
include $_GET['url'];                                         // RFI when allow_url_include=On
readfile('/var/data/' . $_GET['f']);
return response()->download(public_path($request->path));
unlink($uploadDir . $_POST['file']);
move_uploaded_file($_FILES['f']['tmp_name'], $dir . $_FILES['f']['name']);   // name is attacker-set

// SAFE: allow-list
$pages = ['home' => 'home.php', 'about' => 'about.php'];
include __DIR__ . '/pages/' . ($pages[$_GET['p']] ?? 'home.php');

// SAFE: canonicalize and verify the prefix
$base = realpath('/var/data');
$path = realpath($base . '/' . $name);
if ($path === false || !str_starts_with($path, $base . DIRECTORY_SEPARATOR)) { abort(404); }
```

- `allow_url_include=On` is a misconfiguration to flag (default Off). `allow_url_fopen=On` (default)
  lets file functions fetch URLs, which feeds SSRF.
- Uploads (CWE-434): `$_FILES['f']['type']` is client-supplied. Allow-list the extension, rename to a random
  name, store outside the web root or with PHP execution off. A `.php`, `.phtml`, `.phar` file under the
  document root is code execution. Laravel `store('dir')` makes a random name; `storeAs('dir', $input)`
  and `getClientOriginalName()` do not.

## XML External Entities (XXE)

CWE-611 | OWASP A02:2025 Security Misconfiguration

- libxml 2.9.0 and later do not substitute entities by default, and `libxml_disable_entity_loader()` is
  deprecated since PHP 8.0 for that reason (verified in the PHP manual). Plain
  `simplexml_load_string($xml)` or `DOMDocument::loadXML($xml)` on PHP 8.x is not an XXE finding.
- It becomes one when substitution or DTD loading is switched on: `LIBXML_NOENT`, `LIBXML_DTDLOAD`,
  `LIBXML_DTDATTR`, `LIBXML_DTDVALID`.
- `LIBXML_NO_XXE` is available from libxml 2.13 / PHP 8.4 as a positive guard (verified).

```php
// VULNERABLE
$doc->loadXML($userXml, LIBXML_NOENT | LIBXML_DTDLOAD);
$x = simplexml_load_string($userXml, 'SimpleXMLElement', LIBXML_NOENT);

// SAFE
$doc->loadXML($userXml, LIBXML_NONET);
```

## Type Juggling

CWE-697, CWE-843 | OWASP A07:2025 Authentication Failures (when it gates auth)

PHP 8.0 changed number-to-non-numeric-string comparison (`0 == "foo"` is false now, verified). Other
bypasses remain on 8.x; PHP 7 code has all of them.

```php
// VULNERABLE: magic hashes - "0e462097431906509019562988736854" == "0e830400451993494058024219903391"
if (md5($input) == $storedHash) { ... }
if ($token == $expected) { ... }                              // two numeric strings in "0e..." form compare equal

// SAFE
if (hash_equals($expected, $token)) { ... }
if ($a === $b) { ... }

in_array($_GET['id'], $allowedIds);                           // FLAG when it guards access
in_array($_GET['id'], $allowedIds, true);                     // SAFE

```

## Variable Injection and Mass Assignment

CWE-621, CWE-915 | OWASP A06:2025 Insecure Design, A01:2025 Broken Access Control

```php
// VULNERABLE: attacker overwrites any local variable ($isAdmin, $path ...)
extract($_REQUEST);   extract($_POST, EXTR_OVERWRITE);
foreach ($_GET as $k => $v) { $$k = $v; }

// SAFE
extract($trustedRow, EXTR_SKIP);
$name = $_POST['name'] ?? '';
```

`parse_str($qs)` without a result array: PHP 8.0 requires the second argument (verified). On 7.x it
imported variables into the local scope (flag).

```php
// VULNERABLE: any column in the request is writable (is_admin, role, tenant_id)
class User extends Model { protected $guarded = []; }
User::create($request->all());   $user->fill($request->all())->save();
$user->update($request->input());   User::forceCreate($request->all());   User::unguard();

// SAFE
class User extends Model { protected $fillable = ['name', 'email']; }
$user->update($request->validated());                         // FormRequest rules
$user->update($request->only(['name', 'email']));
```

- `$fillable` containing `role`, `is_admin`, `password`, `tenant_id`, `user_id` is a finding when the
  model is filled from a request.
- IDOR (CWE-639): `Model::find($request->id)` with no `Gate`, policy or ownership scope. Look for
  `$this->authorize()`, `can:` middleware, `->where('user_id', auth()->id())`.

## Cross-Site Scripting

CWE-79 | OWASP A05:2025 Injection

```php
// VULNERABLE
echo $_GET['q'];   <?= $user->bio ?>
{!! $comment->body !!}                                        // Blade raw output
{{ comment.body|raw }}   {% autoescape false %}...{% endautoescape %}   // Twig
new HtmlString($userInput);   new Markup($userInput, 'UTF-8');
return new Response('<h1>' . $name . '</h1>');               // Symfony, text/html built from input

// SAFE
{{ $x }}   {{ x }}   {{ x|e('html_attr') }}   {{ Js::from($data) }}   // Laravel JSON helper
htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
```

- Blade `{{ }}` passes through `htmlspecialchars`; `{!! !!}` does not (verified in the Laravel docs).
- Twig `|raw` marks a value safe and skips autoescape (verified). HTML autoescape is on by default in a
  stock environment (unverified here; check the `autoescape` option / `twig.yaml`).
- Escaping is context-bound: HTML escaping does not protect `href="javascript:..."`, inline `<script>`,
  `onclick=` or `<style>`. Validate URL schemes (`http`, `https`, relative).

## CSRF

CWE-352 | OWASP A01:2025 Broken Access Control

```php
// Laravel
protected $except = ['*'];                                    // FLAG (VerifyCsrfToken)
protected $except = ['api/*', 'payment/callback'];            // CHECK: cookie-authenticated routes?
$middleware->validateCsrfTokens(except: ['*']);               // FLAG (Laravel 11+ bootstrap/app.php)
Route::withoutMiddleware(VerifyCsrfToken::class)->post('/transfer', ...);   // CHECK
Route::get('/delete/{id}', ...);                              // FLAG: state change on GET

```

Stateless token APIs (Bearer header) do not need CSRF. Cookie or session routes do, including those in

## Sessions and Authentication

CWE-384, CWE-613, CWE-1004, CWE-287 | OWASP A07:2025 Authentication Failures

```php
// VULNERABLE: no regeneration after login (fixation)
if (password_verify($pw, $hash)) { $_SESSION['uid'] = $user['id']; }   // call session_regenerate_id(true) first
session_id($_GET['sid']); session_start();                    // id accepted from the request
ini_set('session.use_only_cookies', '0');
```

Laravel `Auth::attempt` plus `session()->regenerate()` is safe; custom login writing session keys is not.
Check `session.cookie_httponly`, `cookie_secure`, `cookie_samesite`, `use_strict_mode`, `use_only_cookies`
(Laravel `config/session.php`: `secure`, `http_only`, `same_site`), login throttling (`throttle` middleware),
user enumeration, reset tokens without expiry.

## Weak Randomness

CWE-330, CWE-338 | OWASP A04:2025 Cryptographic Failures

```php
// VULNERABLE for reset tokens, API keys, CSRF tokens, invitation codes, session ids
$token = md5(rand());   md5(uniqid());                        // uniqid is time-based
$token = substr(str_shuffle($chars), 0, 32);                  // shuffle uses mt_rand
$code  = mt_rand(100000, 999999);   mt_srand($userId);   srand(time());

// SAFE
bin2hex(random_bytes(32));   random_int(100000, 999999);   Str::random(40);   // Laravel, CSPRNG
```


## Password Hashing and Crypto

CWE-327, CWE-328, CWE-916 | OWASP A04:2025 Cryptographic Failures

```php
// VULNERABLE
md5($password);   sha1($password);   hash('sha256', $password);   md5($salt . $password);
password_hash($pw, PASSWORD_DEFAULT, ['salt' => $s]);         // salt option ignored with a warning since PHP 8.0

// SAFE
$hash = password_hash($pw, PASSWORD_DEFAULT);                 // bcrypt; or PASSWORD_ARGON2ID
if (password_verify($pw, $hash) && password_needs_rehash($hash, PASSWORD_DEFAULT)) { /* rehash */ }
```

Other smells: `mcrypt_*` (removed in PHP 7.2, unverified), `openssl_encrypt` with ECB or a fixed IV, AES
without authentication (use `-gcm` or `sodium_crypto_secretbox`), MAC compared with `==` (use
`hash_equals`), hard-coded keys, disabled TLS verification (`CURLOPT_SSL_VERIFYPEER => false`, Guzzle
`'verify' => false`, stream context `verify_peer => false`). `md5` / `sha1` for cache keys or ETags is fine.

## SSRF and Open Redirect

CWE-918, CWE-601 | OWASP A01:2025 Broken Access Control

```php
// VULNERABLE: user-controlled URL reaches internal services and cloud metadata
file_get_contents($_GET['url']);
$ch = curl_init($request->input('url'));
Http::get($request->input('callback'));                       // Laravel HTTP client
$client->request('GET', $url);                                // Guzzle / Symfony HttpClient
simplexml_load_file($url);   getimagesize($url);   copy($url, $dst);   // URL wrappers

// VULNERABLE: open redirect (CWE-601)
header('Location: ' . $_GET['next']);   return redirect($request->input('url'));

// SAFE: relative path only
$to = $request->input('to');
if (!str_starts_with($to, '/') || str_starts_with($to, '//') || str_contains($to, '\\')) { $to = '/'; }
```

Also CHECK webhooks, avatar-by-URL, HTML-to-PDF, import-from-URL. Baseline: scheme and host allow-list; resolve the host and test every IP against private ranges (`127.0.0.0/8`,
`10/8`, `172.16/12`, `192.168/16`, `169.254.169.254`, `::1`, `fc00::/7`), connect to the resolved IP
(DNS rebinding), and disable redirects or re-validate each hop (`CURLOPT_FOLLOWLOCATION`, Guzzle
`allow_redirects`). `FILTER_VALIDATE_URL` checks syntax, not safety (unverified for non-HTTP schemes).

## Header Injection and Host Trust

CWE-113, CWE-644 | OWASP A05:2025 Injection, A02:2025 Security Misconfiguration

- `header()` rejects embedded newlines in modern PHP, so classic CRLF splitting is mostly gone (unverified).
  Still check `mail()` headers built from input (`\r\n` adds `Bcc`) and raw socket writes of headers.
- `$_SERVER['HTTP_HOST']`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto` are client
  controlled unless a trusted proxy overwrites them. Flag `'https://' . $_SERVER['HTTP_HOST'] . '/reset?token=' . $t`
  (poisoned reset link) and `HTTP_X_FORWARDED_FOR` used for rate limits or allow-lists. Use
  `config('app.url')`; Laravel `trustProxies(at: [...])`, Symfony `framework.trusted_proxies` / `trusted_hosts`.

## Debug and Information Exposure

CWE-209, CWE-215, CWE-532 | OWASP A02:2025 Security Misconfiguration, A10:2025 Mishandling of Exceptional Conditions

Flag in production: `APP_DEBUG=true` (Laravel shows traces and env values), `display_errors=On`, any
reachable `phpinfo();`, a committed `APP_KEY`, `echo $e->getMessage()` or `var_dump($e)` to the user (SQL
text, paths, DSN passwords). Symfony: dev front controller (`app_dev.php`) or `_profiler` / `_wdt` reachable in production. Also
Telescope, Horizon, Debugbar, Adminer, phpMyAdmin without authentication; `.env`, `.git`,
`composer.lock`, `*.bak`, `*.sql` under the web root; `storage/logs/laravel.log` reachable; logs that
hold passwords, tokens or card numbers (CWE-532). Missing audit logging of auth events and access
denials is A09:2025 Security Logging & Alerting Failures.

## PHP-FPM / Web Server Misconfiguration (brief)

CWE-16 | OWASP A02:2025 Security Misconfiguration
  non-PHP files as PHP.
- Document root is the project root, not `public/`: exposes `.env`, `vendor/`, `storage/`.
- PHP-FPM listening on a reachable TCP port (`listen = 0.0.0.0:9000`): unauthenticated FastCGI is code execution.
- Supply chain (A03:2025 Software Supply Chain Failures): no `composer.lock`, `composer audit` not run,
  committed `vendor/` with outdated packages, install scripts that pipe `curl` to `sh`.

## Grep Patterns

```bash
grep -rnE "(whereRaw|orderByRaw|selectRaw|havingRaw|groupByRaw|DB::(raw|select|statement)|createQuery|executeQuery|->query|mysqli_query)\(.*(\$_(GET|POST|REQUEST)|\$request|\"[^\"]*\$)" --include="*.php"
grep -rnE "\b(exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec|eval|assert|create_function)\s*\(|escapeshellcmd|fromShellCommandline|call_user_func(_array)?\s*\(\s*\$|new\s+\$" --include="*.php"
grep -rnE "unserialize\s*\(|phar://|->getMetadata\(|allow_url_include|\b(include|require)(_once)?\s*\(?[^;]*\$_(GET|POST|REQUEST)|move_uploaded_file" --include="*.php" --include="*.ini"
grep -rnE "LIBXML_NOENT|LIBXML_DTDLOAD|SUBST_ENTITIES|md5\([^)]*\)\s*==[^=]|strcmp\(|in_array\([^,)]*,[^,)]*\)|extract\s*\(\s*\$_" --include="*.php"
grep -rnE "\$guarded\s*=\s*\[\s*\]|forceFill|forceCreate|unguard\(|->(fill|update)\(\$request->(all|input)\(|::create\(\$request->all" --include="*.php"
grep -rnE "\{!!|@php|\|\s*raw|autoescape\s+false|new HtmlString|VerifyCsrfToken|validateCsrfTokens|csrf_protection" --include="*.php" --include="*.twig" --include="*.yaml"
grep -rnE "\b(rand|mt_rand|uniqid|str_shuffle|md5|sha1)\s*\(|HTTP_HOST|HTTP_X_FORWARDED|header\s*\(\s*['\"]Location|(curl_init|file_get_contents|Http::(get|post))\s*\(\s*\$" --include="*.php"
grep -rnE "APP_DEBUG\s*=\s*true|phpinfo\s*\(|display_errors\s*=\s*(On|1)|APP_KEY=" --include="*.php" --include="*.env*" --include="*.ini"
```

## Checklist

1. Entry points listed; each input traced to a sink (SQL, shell, callable, `unserialize`, include, file path, XML, URL fetch, redirect, template).
2. No `*Raw` / `where($column)` / `orderBy($column)` with request text; no shell string with input; no user-chosen callable, class or method.
3. No `unserialize` of external data (or `allowed_classes` plus HMAC); XML without `LIBXML_NOENT`; strict comparisons on auth paths.
4. No `$guarded = []` or `fill($request->all())`; authorisation on every object access; no `{!! !!}` / `|raw` on request data; CSRF exclusions reviewed.
5. Secrets from `random_bytes`; `password_hash`; outbound URLs allow-listed; `Host` / `X-Forwarded-*` untrusted; debug off in production.

Report only findings where untrusted input reaches the sink, or where a configuration is demonstrably unsafe.
