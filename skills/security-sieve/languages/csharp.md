<!-- SPDX-License-Identifier: Apache-2.0 -->
# C# / .NET / ASP.NET Core Security Patterns

Targets C# on .NET 6 and later: ASP.NET Core (MVC, Web API, minimal APIs, Razor, Blazor), EF Core,
ADO.NET and Dapper. Classic .NET Framework differences are noted where they matter. Further reading,
not copied here: [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html),
[ASP.NET Core security docs](https://learn.microsoft.com/en-us/aspnet/core/security/),
[EF Core: SQL queries](https://learn.microsoft.com/en-us/ef/core/querying/sql-queries).

This guide follows the "Do not flag" section of `SKILL.md`. Denial of service, missing rate limits and
missing hardening (headers, CORS shape, `RequireHttpsMetadata = false`, Swagger exposed, no HSTS, no
audit log, unencrypted storage) are not findings on their own. Each needs a concrete exploit path.

## Framework Detection

| Indicator | Stack |
|-----------|-------|
| `Microsoft.NET.Sdk.Web`, `WebApplication.CreateBuilder`, `Startup.cs` | ASP.NET Core |
| `[ApiController]`, `ControllerBase`, `[Route]`, `IActionResult` | MVC / Web API controllers |
| `*.cshtml`, `*.razor`, `app.MapGet(` | Razor, Blazor, minimal APIs |
| `DbContext`, `DbSet<`, `Microsoft.EntityFrameworkCore` | EF Core |
| `SqlConnection`, `SqlCommand`, `using Dapper;` | ADO.NET, Dapper |
| `web.config`, `Global.asax` | .NET Framework |

Attacker input: action parameters (`[FromRoute]`, `[FromQuery]`, `[FromBody]`, `[FromForm]`,
`[FromHeader]`, unannotated simple parameters), `Request.Query`, `Request.Form`, `Request.Headers`,
`Request.Cookies`, `IFormFile.FileName`, `Request.Host`, and data a user stored earlier. Server-side:
`IConfiguration`, `IOptions<T>`, environment variables, `IWebHostEnvironment`.

## Safe Patterns (Do Not Flag)

```csharp
// SAFE: deployment configuration is not attacker input
var url = _config["Billing:BaseUrl"] + "/v1/invoices";        // NOT SSRF
File.ReadAllText(Path.Combine(_env.ContentRootPath, "templates", "mail.html"));   // constants, NOT traversal

// SAFE: parameters
var cmd = new SqlCommand("SELECT Id FROM Orders WHERE Id = @id AND TenantId = @tenant", conn);
cmd.Parameters.Add("@id", SqlDbType.Int).Value = orderId;
db.Orders.Where(o => o.Id == orderId && o.TenantId == tenantId);
db.Orders.FromSql($"SELECT * FROM Orders WHERE Id = {orderId}");   // EF Core 7+, a parameter
conn.QuerySingleOrDefault<Order>("SELECT * FROM Orders WHERE Id = @orderId", new { orderId });
```

Also not findings: `[AllowAnonymous]` on a login page or health check, a Bearer-token API without
antiforgery tokens, `UseDeveloperExceptionPage` behind `IsDevelopment()`, and secrets read from User
Secrets, environment variables or a vault.

## Broken Object-Level Authorization (IDOR)

CWE-639, CWE-284 | OWASP A01:2025 Broken Access Control

Class-level `[Authorize]` is authentication: it proves a caller is logged in, not that the caller may
touch this row. The finding is an action that takes an identifier and loads the object without any
owner or tenant condition.

```csharp
[Authorize]
[ApiController]
public class OrdersController : ControllerBase
{
    // VULNERABLE: any logged-in user reads any order by guessing ids
    [HttpGet("orders/{orderId}")]
    public IActionResult GetOrder(int orderId)
    {
        var order = _repo.Query("SELECT * FROM Orders WHERE ID = @id", new { id = orderId });
        return Ok(order);
    }

    // The sibling DeleteOrder(int orderId) calls _access.UserOwnsOrder(User, orderId): the check exists here
}
```

Method: find how this codebase expresses ownership (`UserOwnsOrder`, `WHERE TenantId = @tenant`, a
global query filter, `IAuthorizationService.AuthorizeAsync`). List every action that takes an id, key
or GUID for the same entity and find the ones that skip it. The sibling that checks is the evidence
that the check is required.

```csharp
// SAFE: an owner condition in the query, or (preferred): resource-based authorization, one handler for every action
var order = await db.Orders.FindAsync(orderId);
if (order is null) return NotFound();
var result = await _authz.AuthorizeAsync(User, order, OrderOperations.Read);
if (!result.Succeeded) return Forbid();
```

For refutation:
- An EF Core global query filter (`HasQueryFilter(o => o.TenantId == _tenant.Id)`) already scopes
  `DbSet` queries. `IgnoreQueryFilters()` and raw SQL bypass it.
- A caller-supplied tenant id is the same bug: `GET /reports?organization_id=7` where the code uses the
  parameter directly instead of the tenant claim from the validated token. Report it when nothing ties
  the parameter to the caller.
- A role check on the action settles that action; a class-wide role does not stop a cross-tenant read.

## Anonymous Token Endpoints and Authentication Bypass

CWE-287, CWE-306 | OWASP A07:2025 Authentication Failures

```csharp
// VULNERABLE: anyone who knows one identifier receives a signed JWT for that account
[AllowAnonymous]
[HttpPost("token/{deviceGuid}")]
public IActionResult IssueToken(Guid deviceGuid)
{
    var user = _users.FindByGuid(deviceGuid);
    return Ok(new { token = _jwt.Create(user) });
}
```

A GUID is an identifier, not a secret. The finding stands when the same identifier is disclosed
somewhere an attacker can read it: a list endpoint, a public profile, a URL, an unauthenticated
response. Name that second hop in the exploit scenario. A GUID never exposed and delivered only to
its owner is a weaker case: score it lower.

## SQL Injection

CWE-89 | OWASP A05:2025 Injection

Parameters protect values. Identifiers (table, column, `ORDER BY` target and direction) cannot be
parameters and need an allow-list.

### ADO.NET

```csharp
// VULNERABLE: text built from request data
var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
cmd.CommandText += " AND Role = '" + role + "'";
cmd.CommandText = string.Format("SELECT * FROM Users WHERE Name = '{0}'", name);
cmd.CommandText = $"SELECT * FROM Users WHERE Name = '{name}'";   // $"" here is concatenation

// VULNERABLE: dynamic ORDER BY
cmd.CommandText = "SELECT * FROM Orders ORDER BY " + sortColumn + " " + direction;

// SAFE: column from a Dictionary<string,string> allow-list, direction from a "desc" ? "DESC" : "ASC" test
cmd.CommandText = $"SELECT * FROM Orders ORDER BY {col} {dir}";
```

A stored procedure called as `"EXEC GetUser '" + name + "'"` is injection; so is one that runs `EXEC(@sql)` on a built string.

### EF Core

Verified in the EF Core documentation: `FromSql` (EF Core 7.0 and later) and `FromSqlInterpolated`
"are safe against SQL injection, and always integrate parameter data as a separate SQL parameter";
`FromSqlRaw` "can be vulnerable to SQL injection attacks, if improperly used".

```csharp
// VULNERABLE: interpolation inside the Raw variants is plain string building
db.Orders.FromSqlRaw($"SELECT * FROM Orders WHERE Name = '{name}'");
db.Orders.FromSqlRaw("SELECT * FROM Orders WHERE Name = '" + name + "'");
db.Database.ExecuteSqlRaw($"DELETE FROM Orders WHERE Id = {id}");
db.Database.SqlQueryRaw<int>($"SELECT Id FROM Orders WHERE Name = '{name}'");

// SAFE
db.Orders.FromSqlRaw("SELECT * FROM Orders WHERE Name = {0}", name);   // placeholder becomes a parameter
db.Orders.FromSqlRaw("SELECT * FROM Orders WHERE Name = @n", new SqlParameter("n", name));
db.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE Name = {name}");
```

Refutation: a `FromSqlRaw` whose first argument is a constant is not a finding. A user value in an
interpolation hole of `FromSql` cannot inject through that value (a column name there simply fails,
because identifiers cannot be parameters). `System.Linq.Dynamic.Core` `.OrderBy(userString)` parses an
expression: treat it as a sink and look for an allow-list.

### Dapper

```csharp
// VULNERABLE: Dapper does not turn $"" into parameters
conn.Query<Order>("SELECT * FROM Orders WHERE Name = '" + name + "'");
conn.ExecuteAsync($"UPDATE Orders SET Status = '{status}' WHERE Id = {id}");
```

## Command Injection

CWE-78 | OWASP A05:2025 Injection

```csharp
// VULNERABLE: shell with request data
Process.Start("cmd.exe", "/c ping " + host);
Process.Start(new ProcessStartInfo { FileName = tool, Arguments = $"-i {file}", UseShellExecute = true });

// BETTER: no shell, one entry per argument
var psi = new ProcessStartInfo("convert") { UseShellExecute = false };
psi.ArgumentList.Add("--");   psi.ArgumentList.Add(file);
```

`ArgumentList` keeps shell metacharacters inert, but a value starting with `-` is still read as an
option by the program: put `--` first or allow-list. With `UseShellExecute = true`, `FileName` can be
a document or URL the OS opens, so a user-controlled `FileName` is a finding. Report only when a
request value reaches `FileName` or `Arguments`.

## Deserialization

CWE-502 | OWASP A08:2025 Software or Data Integrity Failures

```csharp
// VULNERABLE: Newtonsoft.Json takes type names from the payload
var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };   // also All, Objects, Arrays
var obj = JsonConvert.DeserializeObject(body, settings);

// VULNERABLE: formatters that rebuild arbitrary object graphs
new BinaryFormatter().Deserialize(stream);
new NetDataContractSerializer().Deserialize(stream);
new LosFormatter().Deserialize(viewState);   new SoapFormatter().Deserialize(stream);
new JavaScriptSerializer(new SimpleTypeResolver()).Deserialize<object>(json);   // .NET Framework

```

Version note, verified in Microsoft's BinaryFormatter security guide: the page lists `BinaryFormatter`,
`SoapFormatter`, `NetDataContractSerializer`, `LosFormatter` and `ObjectStateFormatter` as insecure,
calls `BinaryFormatter.Deserialize` never safe with untrusted input, and says that starting in .NET 9
the in-box `BinaryFormatter` throws on use. On .NET 8 and earlier, and on .NET Framework, it still
runs. On a .NET 9 project, look for a compatibility package that brings it back.

`TypeNameHandling` other than `None` is a finding when the data comes from a request, cookie, queue or
upload. A `SerializationBinder` allow-list narrows the risk; read it. Data the server wrote and signs is
not a finding.

## XML External Entities (XXE)

CWE-611 | OWASP A02:2025 Security Misconfiguration

Verified in the .NET documentation: `XmlReaderSettings.XmlResolver` defaults to `null` since .NET
Framework 4.5.2, and `XmlTextReader.DtdProcessing` defaults to `Parse`. The default resolver of
`XmlDocument` and `XmlTextReader` on .NET Core was not confirmed (unverified): read the code for an
explicit resolver instead of assuming.

```csharp
// VULNERABLE: resolver or DTD parsing switched on, XML from a request or an upload
var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };   // then doc.LoadXml(userXml)
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
var tr = new XmlTextReader(stream);                    // CHECK: DtdProcessing is Parse by default, look at the resolver

// SAFE: DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null
```

XXE needs DTD processing and a resolver able to fetch the target. Entity expansion without a resolver
is a DoS class and is not reported.

## Path Traversal and File Access

CWE-22, CWE-73 | OWASP A01:2025 Broken Access Control

`Path.Combine(basePath, userInput)` ignores the base when `userInput` is rooted. Verified in the
`Path.Combine` documentation: "if an argument other than the first contains a rooted path, any previous
path components are ignored", and the page advises `Path.Join` when later arguments are user input.
So `Path.Combine("/srv/files", "/etc/passwd")` is `/etc/passwd` even when `..` is filtered.

```csharp
// VULNERABLE
var path = Path.Combine(_root, fileName);
return PhysicalFile(path, "application/octet-stream");
using var fs = File.Create(Path.Combine(uploadDir, formFile.FileName));   // FileName is client-set

// SAFE: canonicalize, then require the base directory as a prefix
var root = Path.GetFullPath(_root) + Path.DirectorySeparatorChar;
var full = Path.GetFullPath(Path.Combine(_root, fileName));
if (!full.StartsWith(root, StringComparison.Ordinal)) return NotFound();
```

`Path.GetFileName(userInput)` suits single-file lookups (on Linux a backslash is a legal name
character). Generating the stored name server-side avoids the client name entirely. Archive extraction
by hand (`ZipArchiveEntry.FullName` joined to a destination) needs the same prefix check.

Uploads (CWE-434): `IFormFile.ContentType` is client-supplied; ASP.NET Core does not execute files
from `wwwroot`, so the realistic finding is stored XSS through served HTML or SVG.

## Open Redirect

CWE-601 | OWASP A01:2025 Broken Access Control

```csharp
// VULNERABLE
return Redirect(returnUrl);                   // also RedirectPermanent
Response.Redirect(Request.Query["next"]);

// SAFE
if (!Url.IsLocalUrl(returnUrl)) returnUrl = "/";
return LocalRedirect(returnUrl);              // throws on a non-local URL
```

## Cross-Site Scripting

CWE-79 | OWASP A05:2025 Injection

```csharp
// VULNERABLE
@Html.Raw(Model.Bio)                              // Razor
<div>@((MarkupString)Model.Html)</div>            // Blazor: MarkupString renders raw HTML
return Content("<h1>" + name + "</h1>", "text/html");
new HtmlString(userInput);

```

Encoding does not stop `href="javascript:..."`: validate the scheme of user-supplied URLs. Blazor
encodes normal output; the sinks are `MarkupString` and JavaScript interop that evaluates strings. A
sanitizer before `Html.Raw` helps only if its allow-list is sound; read it.

## CSRF

CWE-352 | OWASP A01:2025 Broken Access Control

```csharp
// CHECK: cookie-authenticated state change with the token turned off
[IgnoreAntiforgeryToken]
[HttpPost] public IActionResult Transfer(TransferModel m) { ... }

```

Razor Pages validate antiforgery tokens by default; MVC controllers need `[ValidateAntiForgeryToken]`,
`[AutoValidateAntiforgeryToken]` or the global filter. Report an exclusion or omission only when the
endpoint authenticates by cookie (or other ambient credentials, such as Windows authentication) and
changes state. Bearer-token APIs are not CSRF targets.

## Mass Assignment (Over-Posting)

CWE-915 | OWASP A01:2025 Broken Access Control, A06:2025 Insecure Design

```csharp
// VULNERABLE: the EF entity is the request model; the client sets IsAdmin, TenantId, Balance
[HttpPut("users/{id}")]
public async Task<IActionResult> Update(int id, [FromBody] User user)
{
    db.Entry(user).State = EntityState.Modified;
    await db.SaveChangesAsync();
}
await TryUpdateModelAsync(existingUser);          // binds every public property

// SAFE: a DTO (record UpdateUserDto(string Name, string Email)) mapped field by field onto the loaded entity
```

`[Bind("Name,Email")]` or `[BindNever]` also narrows binding. The finding needs a sensitive property
(role, admin flag, tenant id, owner id, price) on the bound type that the action persists.
`Entry(user).State = Modified` with a client id also updates any row, which is the IDOR above.

## JWT and Token Validation

CWE-347, CWE-345 | OWASP A07:2025 Authentication Failures

```csharp
// VULNERABLE: signature or claims checks turned off
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuerSigningKey = false,     // forged tokens accepted
    ValidateIssuer = false, ValidateAudience = false, ValidateLifetime = false, RequireSignedTokens = false,
};
// VULNERABLE: claims read without validation, then trusted
var jwt = new JwtSecurityTokenHandler().ReadJwtToken(raw);   // does not verify the signature
var userId = jwt.Claims.First(c => c.Type == "sub").Value;
```

`ValidateIssuerSigningKey = false` or `RequireSignedTokens = false` is a finding: anyone can mint a
token. `ValidateIssuer = false` or `ValidateAudience = false` alone depends on context: it matters when
services share a signing key; say so in the scenario or score it down.
`RequireHttpsMetadata = false` is hardening only. A signing key hard-coded in source or committed
configuration, short enough to guess, or shared across environments is a finding (CWE-798).

## Secrets in Source and Configuration

CWE-798, CWE-312 | OWASP A07:2025 Authentication Failures, A02:2025 Security Misconfiguration

Look in `appsettings*.json`, `web.config` and `app.config` connection strings, `*.PublishSettings` and
`*.pubxml` (deployment passwords), `launchSettings.json`, and compiled output committed by accident
(`bin/`, `obj/`, `publish/`): those copies keep configuration after the source was cleaned. Search git
history for the same files; a secret removed from HEAD can still be live.

A finding needs a live-looking credential: a real host, a non-placeholder password, a key with provider
structure. Empty values, `"<set in vault>"` and `localhost` development settings are not findings.

A hard-coded passphrase in SQL Server `EncryptByPassPhrase` / `DecryptByPassPhrase` is a finding only
when an attacker has a read path to the ciphertext (an endpoint, a backup, a shared database).

## Cryptography and Randomness

CWE-330, CWE-327, CWE-916, CWE-208 | OWASP A04:2025 Cryptographic Failures

```csharp
// VULNERABLE for reset tokens, API keys, session ids, invitation codes
var token = new Random().Next(100000, 999999).ToString();

// SAFE
var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

// VULNERABLE: fast hash for passwords
MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
// SAFE
var hash = new PasswordHasher<AppUser>().HashPassword(user, password);   // ASP.NET Core Identity, PBKDF2
var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);

// Secret comparison: == on a signature is variable-time; use CryptographicOperations.FixedTimeEquals
```

`Random` is fine for shuffling a UI list. MD5 and SHA1 for ETags, cache keys and checksums are not
findings. A timing finding needs a remote caller who can measure it and a secret worth guessing (an
HMAC, a token). Other smells: DES, 3DES, `CipherMode.ECB`, a fixed IV, AES-CBC without a MAC, hard-coded
keys, and `ServerCertificateCustomValidationCallback = (_, _, _, _) => true` toward a real remote host.

## SSRF

CWE-918 | OWASP A01:2025 Broken Access Control

A request-supplied URL passed to `HttpClient` (`await _http.GetAsync(request.CallbackUrl)`) reaches
internal hosts and cloud metadata. Baseline: scheme and host allow-list, resolve the host and refuse private ranges (`127.0.0.0/8`,
`10/8`, `172.16/12`, `192.168/16`, `169.254.169.254`, `::1`, `fc00::/7`), connect to the resolved
address, and set `AllowAutoRedirect = false` or re-validate each hop. Webhook registration,
avatar-by-URL, import-from-URL and HTML-to-PDF are the usual places. A configured base address with a
user value only in the path is not SSRF unless the value can start with `//host` or contain `@`.

## Information Exposure

CWE-209, CWE-532 | OWASP A02:2025 Security Misconfiguration

Report what leaks a secret: `UseDeveloperExceptionPage()` outside an environment check, `ex.ToString()`
returned to the caller, logs holding passwords or tokens. Swagger in production is hardening.

## Grep Patterns

Single quotes keep the shell from touching `$` and `"`. These hits are candidates: each still goes
through the source-to-sink check and the refutation pass.

```bash
rg -n '(new SqlCommand|CommandText\s*\+?=|FromSqlRaw|ExecuteSqlRaw|SqlQueryRaw).*(\$"|\+\s*[A-Za-z_"]|string\.Format)' -g '*.cs'
rg -n '\.(Query|QueryFirst|QueryFirstOrDefault|QuerySingle|Execute|ExecuteScalar)(Async)?(<[^>]+>)?\(\s*(\$"|"[^"]*"\s*\+)' -g '*.cs'
rg -n 'ORDER BY[^"]*"\s*\+|ORDER BY \{' -g '*.cs'
rg -n '(ValidateIssuer|ValidateAudience|ValidateLifetime|ValidateIssuerSigningKey|RequireSignedTokens)\s*=\s*false|RequireHttpsMetadata\s*=\s*false' -g '*.cs'
rg -n 'TypeNameHandling\.(All|Auto|Objects|Arrays)|\b(BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|ObjectStateFormatter|SimpleTypeResolver)\b' -g '*.cs'
rg -n 'XmlResolver\s*=\s*new|DtdProcessing\.Parse|ProhibitDtd\s*=\s*false|new XmlTextReader\(' -g '*.cs'
rg -n 'Process\.Start\(|UseShellExecute\s*=\s*true|\.Arguments\s*=.*(\+|\$")' -g '*.cs'
rg -n 'Path\.Combine\(|PhysicalFile\(|File\.(ReadAll|Open|Delete|WriteAll|Copy|Move)\w*\(' -g '*.cs'
rg -n '\bRedirect(Permanent)?\(|Html\.Raw|MarkupString|IgnoreAntiforgeryToken' -g '*.cs' -g '*.cshtml' -g '*.razor'
rg -n 'AllowAnonymous|\[Http\w+\("[^"]*token' -g '*.cs'
rg -n 'public .*\((\[From\w+\]\s*)?(int|long|Guid)\s+\w*[iI]d\b' -g '*.cs'
rg -n -i '\[From(Query|Route|Body)\][^,)]*\b(organization|tenant|company|account)\w*' -g '*.cs'
rg -n 'new Random\(|MD5\.Create|SHA1\.Create|MD5CryptoServiceProvider|CipherMode\.ECB|EncryptByPassPhrase|DecryptByPassPhrase' -g '*.cs' -g '*.sql'
rg -n '\[FromBody\]\s*[A-Z]\w*\s+\w+|EntityState\.Modified|\.Update\(\w+\)' -g '*.cs'
rg -n --hidden -i '(password|pwd|secret|apikey|accountkey|sharedaccesskey)"?\s*[=:]\s*"?[^";\s{$%]{4,}' -g 'appsettings*.json' -g '*.config' -g '*.PublishSettings' -g '*.pubxml' -g 'launchSettings.json'
```

The id-parameter pattern lists actions that take an identifier; compare with the ones calling the
ownership check (`rg -n 'UserOwns|CheckAccess|AuthorizeAsync|TenantId' -g '*.cs'`).

## Checklist

1. Every id, tenant id or GUID parameter traced to a query; ownership or tenant condition found, or its absence shown by a sibling that has it.
2. Anonymous token and login endpoints: what identifier is enough, and where else it is disclosed.
3. No SQL text built with `+`, `$""` or `string.Format`; `FromSqlRaw`, `ExecuteSqlRaw`, Dapper read; `ORDER BY` from an allow-list.
4. JWT validation keeps signature, issuer, audience and lifetime checks; no `ReadJwtToken` trust.
5. No `TypeNameHandling` other than `None`, no `BinaryFormatter` family, no XML resolver on untrusted data.
6. Process, file path, redirect, `Html.Raw` and antiforgery sinks guarded; entities not bound from `[FromBody]`; secrets and crypto checked.

Report only findings where untrusted input reaches the sink, or where a configuration is demonstrably unsafe.
