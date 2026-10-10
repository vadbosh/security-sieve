<!-- SPDX-License-Identifier: Apache-2.0 -->
# Java / Spring Security Patterns

Targets Java 8 and later: Spring Boot and Spring MVC, WebFlux, Spring Security, Spring Data JPA and
Hibernate, JDBC and `JdbcTemplate`, MyBatis, plain Servlets and Jakarta EE. Kotlin on Spring reads the
same way. Further reading, not copied here:
[OWASP Java cheat sheets](https://cheatsheetseries.owasp.org/Glossary.html),
[OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html),
[OWASP Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html),
[Trail of Bits: Java sharp edges](https://github.com/trailofbits/skills/blob/main/plugins/sharp-edges/skills/sharp-edges/references/lang-java.md),
[Spring Security reference](https://docs.spring.io/spring-security/reference/).

This guide follows the "Do not flag" section of `SKILL.md`. Denial of service, missing rate limits and
missing hardening (headers, CORS shape, `server.error.include-stacktrace`, Swagger exposed, no audit
log, an old library with no reachable vulnerable call) are not findings on their own. Each needs a
concrete exploit path.

## Framework Detection

| Indicator | Stack |
|-----------|-------|
| `pom.xml` / `build.gradle` with `spring-boot-starter-web`, `@SpringBootApplication` | Spring Boot, MVC on Servlets |
| `spring-boot-starter-webflux`, `Mono<`, `Flux<`, `RouterFunction` | WebFlux |
| `@RestController`, `@Controller`, `@GetMapping`, `@RequestMapping` | Spring controllers |
| `spring-boot-starter-security`, `SecurityFilterChain`, `WebSecurityConfigurerAdapter` | Spring Security |
| `extends OncePerRequestFilter`, `implements HandlerInterceptor`, `@Aspect` | Hand-written authentication or authorisation |
| `JpaRepository`, `@Query`, `EntityManager`, `@Entity` | Spring Data JPA, Hibernate |
| `JdbcTemplate`, `NamedParameterJdbcTemplate`, `Connection.prepareStatement` | JDBC |
| `*Mapper.xml`, `@Select`, `org.apache.ibatis` | MyBatis |
| `extends HttpServlet`, `web.xml`, `*.jsp` | Servlets, JSP |

Attacker input: `@PathVariable`, `@RequestParam`, `@RequestBody`, `@RequestHeader`, `@CookieValue`,
`@MatrixVariable`, `@ModelAttribute` objects bound from request parameters, `HttpServletRequest`
getters (`getParameter`, `getHeader`, `getRequestURI`, `getInputStream`),
`MultipartFile.getOriginalFilename()`, messages from Kafka, SQS or RabbitMQ when their producer is
outside the trust boundary, and data a user stored earlier. Server-side: `@Value`, `Environment`,
`@ConfigurationProperties`, `application.yml` / `application.properties`.

## Safe Patterns (Do Not Flag)

```java
// SAFE: deployment configuration is not attacker input
String url = props.getBillingBaseUrl() + "/v1/invoices";           // NOT SSRF
Path tpl = Paths.get(templateDir, "mail.html");                    // constants, NOT traversal

// SAFE: parameters
jdbc.query("SELECT id FROM orders WHERE id = ? AND tenant_id = ?", mapper, orderId, tenantId);
em.createQuery("select o from Order o where o.id = :id", Order.class).setParameter("id", orderId);
@Query("select o from Order o where o.id = :id and o.tenantId = :tenant")
Optional<Order> find(@Param("id") long id, @Param("tenant") long tenant);
repo.findByIdAndTenantId(orderId, tenantId);                       // derived query, parameters
```

Also not findings: `permitAll()` on a login, sign-up or health endpoint, CSRF switched off for an API
that authenticates only by a bearer token, `/actuator/health` and `/actuator/info` exposed, and secrets
read from the environment or a vault with no literal default.

## Where Identity Comes From

Read this before any authorisation finding. Many Spring code bases do not use Spring Security for it:
a filter puts the caller into the session or a request attribute, and controllers read it back. Find
that path first — the filter, the interceptor, the argument resolver or the base controller — and
answer two questions: which requests does the filter skip, and what does a controller receive when no
one is logged in.

```java
// A filter that only populates identity does not reject anything: a controller that never checks
// the value is reachable anonymously
public class AuthFilter extends OncePerRequestFilter {
    protected void doFilterInternal(...) { tryAuthenticate(request); chain.doFilter(request, response); }
}
```

**`@ModelAttribute` as an identity source.** Verified in the Spring MVC reference: a `@ModelAttribute`
argument is taken from the model when a `@ModelAttribute` method put it there, from the session when
the class lists it in `@SessionAttributes`, and otherwise "obtained through a `Converter` if the model
attribute name matches the name of a request value such as a path variable or a request parameter".

```java
// SAFE only while a @ModelAttribute("accountId") method runs for this controller — in its class
// hierarchy or in a @ControllerAdvice that covers it — and fills the name from the session
@PostMapping("/orders/{orderId}/cancel")
public void cancel(@ModelAttribute("accountId") Optional<Long> account, @PathVariable long orderId)

// VULNERABLE: the same parameter in a controller that does not inherit the populating method.
// Spring converts ?accountId=42 from the request into the caller's identity
```

Check: list the names used this way (`rg -o '@ModelAttribute\((value\s*=\s*)?[A-Za-z_.]+\)' -g '*.java'`),
find each populating method, and look for controllers outside its reach. The runtime behaviour for a
`Optional<Long>` parameter with no populating method was not tested (unverified): if you report it,
say so or confirm it on a running instance.

A caller-supplied identity is the same bug in plain form: `@RequestParam Long accountId`,
`@RequestHeader("X-User-Id")` or a body field `ownerId` used instead of the session or the validated
token.

## Broken Object-Level Authorization (IDOR)

CWE-639, CWE-284 | OWASP A01:2025 Broken Access Control

The authorisation inventory of Step 4, for Spring controllers: one line per handler — its mapping,
whether it takes an id, and how many ownership checks its body contains. Put the names of the project's
own ownership checks in `OWNER`: a check that the object belongs to the caller, not a role check. A
handler with an id and `owner=0` is a candidate, to be confirmed in the service it calls.

```bash
OWNER='verifyOwnership|isOwner|ByIdAndOwnerId|ByIdAndAccountId|ByIdAndTenantId|tenantId *=='   # replace with this project's own names
rg -l -g '*.java' '@(Rest)?Controller\b' . | while read -r f; do
  awk -v f="$f" -v t="$OWNER" '
    /@(Get|Post|Put|Delete|Patch|Request)Mapping/ { if (r != "") print f ":" n, r, "id=" id, "owner=" c
                                                    r = $0; sub(/^[ \t]+/, "", r); n = NR; id = 0; c = 0 }
    r != "" && /@(PathVariable|RequestParam)/ && /[^A-Za-z]([Ii]d|[A-Za-z]+Id|[Uu]uid|[A-Za-z]+Uuid)[^A-Za-z]/ { id = 1 }
    r != "" && $0 ~ t { c++ }
    END { if (r != "") print f ":" n, r, "id=" id, "owner=" c }' "$f"
done | awk '$NF == "owner=0" && $(NF-1) == "id=1"'
```

It reads text, not the compiler's view: a class-level `@RequestMapping` prints a line of its own, and a
check done in the service, a `@PreAuthorize` expression, an aspect or the query itself shows as
`owner=0` and must be read before it is reported.

When most of the list is `owner=0`, the checks live a layer down. Measured on a Spring code base of
1329 handlers: 535 took an id and 436 of those showed no check in the controller. Follow one handler
that is known to be safe into its service, find the check there, and run the same `awk` over the
service implementations with that name in `OWNER` and `/public [^=]*\(/` in place of the mapping
pattern. The candidates are the service methods that take an id and never reach it.

`.authenticated()` in a security chain, a filter that requires a session, or a role check such as
`hasRole('MEMBER')` proves who the caller is, not that the caller may touch this row. The finding is a
handler that takes an identifier and loads or changes the object with no owner or tenant condition.

```java
// VULNERABLE: any logged-in member reads any report by its id
@GetMapping("/reports/{reportId}")
public ReportDto get(@ModelAttribute("accountId") Optional<Long> account, @PathVariable long reportId) {
    checkMemberRole(account);                       // role only
    return converter.convert(reportRepository.findById(reportId).orElseThrow(NotFound::new));
}
// The sibling delete(...) calls checkOwner(account, report): the check exists here
```

Method: find how this code base expresses ownership (`findByIdAndOwnerId`, a `@PreAuthorize("@guard.owns(#id)")`
bean, a Hibernate `@Filter` for the tenant, a service method that compares owner ids). List every
handler that takes an id, an external id or a UUID of the same entity and find the ones that skip it.
The sibling that checks is the evidence that the check is required.

For refutation:
- A Hibernate `@Filter` or `@Where` for the tenant scopes entity queries only while it is enabled;
  native queries and `EntityManager.find` ignore `@Filter`.
- `@PreAuthorize` / `@PostAuthorize` work only with method security enabled
  (`@EnableMethodSecurity`, or `@EnableGlobalMethodSecurity(prePostEnabled = true)` before Spring
  Security 5.6) and only on calls through the Spring proxy: a call from another method of the same
  class skips it.
- Ids compared with `==` on `Long` or `Integer` objects compare references and are equal only inside
  the boxed cache (-128..127). Read what the failing branch does: a check that denies when the ids
  differ fails closed; one that allows on `!=` or falls through fails open.
- A role check on the handler settles that handler; a role on the class does not stop a cross-tenant
  read.
- `@Cacheable` on a controller method, or on a service method whose key leaves out the caller, serves
  the cached answer without running the method body again — and the ownership check inside it. The
  first owner fills the cache; anyone asking for the same key afterwards gets the owner's data. Read
  the `key` / `keyGenerator`: a key with the caller's id in it is safe.

## Mass Assignment

CWE-915 | OWASP A01:2025 Broken Access Control, A06:2025 Insecure Design

```java
// VULNERABLE: the entity is the request body; the client sets role, ownerId, balance, verified
@PutMapping("/users/{id}")
public void update(@PathVariable long id, @RequestBody User user) { userRepository.save(user); }

// VULNERABLE: every matching property copied from the request object
BeanUtils.copyProperties(dto, entity);              // Spring or commons-beanutils, same effect
modelMapper.map(dto, entity);

// SAFE: a DTO with only the editable fields, copied by name onto the loaded entity;
// or BeanUtils.copyProperties(dto, entity, "role", "ownerId") with the sensitive ones excluded
```

`@ModelAttribute User form` binds request parameters onto the object, including nested paths such as
`account.role`. `WebDataBinder.setAllowedFields` in an `@InitBinder` narrows it. The finding needs a
sensitive property on the bound type that the handler persists. `save(user)` with a client id also
overwrites any row, which is the IDOR above.

## SQL and Query Injection

CWE-89, CWE-943 | OWASP A05:2025 Injection

Parameters protect values. Identifiers — table, column, `ORDER BY` target and direction — cannot be
parameters and need an allow-list.

```java
// VULNERABLE: text built from request data
jdbc.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
stmt.executeQuery(String.format("SELECT * FROM users WHERE name = '%s'", name));
em.createQuery("select u from User u where u.name = '" + name + "'");   // JPQL / HQL injection
em.createNativeQuery("SELECT * FROM orders ORDER BY " + sort);

// VULNERABLE: concatenation inside @Query is compiled once, so it is safe only when every
// part is a constant; a SpEL expression that inserts text is the risky case
@Query(value = "select * from orders where status = '" + Status.OPEN + "'", nativeQuery = true)   // constant: SAFE

// SAFE
jdbc.query("SELECT * FROM users WHERE name = ?", mapper, name);
namedJdbc.query("SELECT * FROM users WHERE name = :n", Map.of("n", name), mapper);
```

`ORDER BY` and Spring Data: verified in the Spring Data JPA reference, `Sort` properties "need to match
your domain model", and Spring Data "rejects any `Order` instance containing function calls"; with
`JpaSort.unsafe(…)` "the order string is appended to the query". So `Sort.by(userValue)` on a derived
or `@Query` method is not injection, while `JpaSort.unsafe(userValue)` is. A sort column taken from the
request and concatenated into native SQL or `JdbcTemplate` text is the common real case.

**Hand-made escaping is not a parameter.** A helper that doubles single quotes (`replace("'", "''")`,
an `escapeSql` or `hqlEscape` of the project's own) before the value goes into a string literal looks
safe and is not on MySQL: there a backslash also escapes, so `\'` ends up as an escaped quote followed
by a live one, unless the server runs with `NO_BACKSLASH_ESCAPES` in `sql_mode`. Report the injection
and name the `sql_mode` condition; the fix is a parameter either way.

MyBatis: `#{name}` is a parameter, `${name}` is text substitution — `${}` with request data is
injection, in `*Mapper.xml` and in `@Select`, `@Update`, `@Delete` annotations. Criteria API and
QueryDSL build parameters; read any `cb.literal`, `Expressions.stringTemplate` or raw SQL inside them.

## Command Injection

CWE-78 | OWASP A05:2025 Injection

```java
// VULNERABLE: a shell with request data
Runtime.getRuntime().exec("sh -c convert " + file);
new ProcessBuilder("bash", "-c", "ping " + host).start();

// BETTER: no shell, one element per argument, -- before the user value
new ProcessBuilder("convert", "--", file).start();
```

`Runtime.exec(String)` splits on spaces without a shell, so `;` and `|` are inert there, but an
attacker who controls the first token or an option still wins: a value starting with `-` is read as
an option. Report only when a request value reaches the command or its arguments.

## Expression and Template Injection

CWE-917, CWE-1336 | OWASP A05:2025 Injection

```java
// VULNERABLE: SpEL evaluated from request data with the full context
new SpelExpressionParser().parseExpression(userInput).getValue(new StandardEvaluationContext());
// SAFER: SimpleEvaluationContext.forReadOnlyDataBinding() — no type references, no constructors

// VULNERABLE: a template whose text, not only its data, comes from the user
new Template("t", new StringReader(userTemplate), freemarkerCfg).process(model, out);
Velocity.evaluate(ctx, out, "t", userTemplate);

// VULNERABLE: a @Controller (not @RestController) returning a view name built from input;
// with Thymeleaf the name is parsed as an expression when it contains __${...}__
@GetMapping("/doc") public String doc(@RequestParam String section) { return "docs/" + section; }
```

**Bean Validation messages are templates.** A custom `ConstraintValidator` that puts the rejected
value into the message — `context.buildConstraintViolationWithTemplate(String.format("… %s", value))`
— hands request text to the message interpolator, and Hibernate Validator evaluates `${…}` in it as
Expression Language. An expression in `${…}` sent in a validated field runs on the server, reachable
wherever `@Valid` runs on that DTO, before any check in the handler body. Safe: a constant template with the value passed through
`HibernateConstraintValidatorContext.addMessageParameter` or `addExpressionVariable`, or a message
that does not echo the value. Found this way as the critical finding of a real Spring Boot 2.2 review.

```bash
rg -n 'buildConstraintViolationWithTemplate\(' -g '*.java' .   # then read what goes into the template
```

Templates that the application ships, filled with user data, are output encoding questions (XSS), not
template injection. Email templates edited by administrators are a finding only when a lower-privileged
role can edit them.

## Deserialization

CWE-502 | OWASP A08:2025 Software or Data Integrity Failures

```java
// VULNERABLE: native serialization of attacker bytes (request, cookie, cache, queue, upload)
new ObjectInputStream(in).readObject();
SerializationUtils.deserialize(bytes);              // commons-lang3 and Spring both wrap it
new XMLDecoder(in).readObject();
new XStream().fromXML(xml);                          // without an allow-list of types

// VULNERABLE: Jackson taking the class from the payload
mapper.enableDefaultTyping();                         // or activateDefaultTyping with LaissezFaireSubTypeValidator
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS) Object payload;   // also MINIMAL_CLASS, on Object or a broad base type

// VULNERABLE before SnakeYAML 2.0: new Yaml().load(text) builds any class named in the document
```

`@JsonTypeInfo(use = Id.NAME)` with `@JsonSubTypes` is an allow-list and not a finding. A gadget chain
needs a class on the classpath: name the library (commons-collections, older Spring, Groovy) when the
version is known, and treat its absence as a reason to score down, not to drop — new chains appear. Data
the server wrote and signs is not a finding. Spring Session or a cache in Redis stores serialized
objects: a finding only when an attacker can write to that store.

## XML External Entities (XXE)

CWE-611 | OWASP A02:2025 Security Misconfiguration

The JAXP factories (`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`,
`TransformerFactory`, `SchemaFactory`) and libraries built on them (dom4j `SAXReader`, JDOM
`SAXBuilder`, JAXB `Unmarshaller` on a raw stream, Apache POI on old versions) accept a DOCTYPE unless
configured otherwise. The OWASP XXE Prevention Cheat Sheet gives the per-factory settings: reject
DOCTYPE for DOM and SAX, turn off DTD support and external entities for StAX, deny external access for
`TransformerFactory` and `SchemaFactory`.

```java
// VULNERABLE: XML from a request or upload, factory left at defaults
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.newDocumentBuilder().parse(upload.getInputStream());

// SAFE
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

The finding needs untrusted XML: an upload, a SOAP or XML endpoint, an imported file, a SAML message.
Entity expansion without an external fetch is DoS and is not reported. Office files (`.xlsx`, `.docx`)
are ZIP archives of XML: check the POI version when users upload them.

## Path Traversal and File Access

CWE-22, CWE-73 | OWASP A01:2025 Broken Access Control

Verified in the `Path.resolve` Javadoc: "If the other parameter is an absolute path then this method
trivially returns other". `new File(base, child)` with `..` in `child` walks out of `base` as well.

```java
// VULNERABLE
Path p = Paths.get(uploadDir).resolve(file.getOriginalFilename());     // client-set name
return new FileSystemResource(new File(reportsDir, request.getParameter("name")));

// SAFE: normalise, then require the base as a prefix
Path base = Paths.get(uploadDir).toRealPath();
Path target = base.resolve(name).normalize();
if (!target.startsWith(base)) throw new ForbiddenException();
```

`Path.startsWith` compares path elements; `String.startsWith` on paths accepts `/srv/files-evil`.
Archive extraction (`ZipEntry.getName()`, `TarArchiveEntry.getName()`) joined to a destination needs
the same check (zip slip). `ResourceLoader.getResource(userValue)` accepts `file:`, `classpath:` and
URL prefixes. Uploads: the realistic finding is a file served back with an attacker-chosen type
(stored XSS through HTML or SVG) or written into a directory the server executes from.

## SSRF

CWE-918 | OWASP A01:2025 Broken Access Control

A request-supplied URL passed to `RestTemplate`, `WebClient`, Apache `HttpClient`, OkHttp or
`new URL(u).openConnection()` reaches internal hosts and cloud metadata. Baseline: scheme and host
allow-list, resolve the host and refuse private ranges (`127.0.0.0/8`, `10/8`, `172.16/12`,
`192.168/16`, `169.254.169.254`, `::1`, `fc00::/7`), connect to the resolved address, and turn off
redirects or re-validate each hop. Webhooks, avatar-by-URL, import-from-URL, link previews and
HTML-to-PDF are the usual places. A configured base URL with a user value only in the path is not SSRF
unless the value can start with `//host` or contain `@`. `new URL(userValue)` also accepts `file:` and
`jar:`: reading `file:///etc/passwd` through it is SSRF's local twin.

## Open Redirect

CWE-601 | OWASP A01:2025 Broken Access Control

```java
// VULNERABLE
return "redirect:" + returnUrl;
response.sendRedirect(request.getParameter("next"));
// SAFE: a relative path checked to start with a single "/" and not "//" or "/\", or a host allow-list
```

## Cross-Site Scripting

CWE-79 | OWASP A05:2025 Injection

```java
// VULNERABLE
@GetMapping(value = "/hello", produces = MediaType.TEXT_HTML_VALUE)
public String hello(@RequestParam String name) { return "<h1>" + name + "</h1>"; }
response.getWriter().write(userValue);                       // with an HTML content type
// Thymeleaf th:utext, JSP <%= value %>, ${value} outside <c:out> on old JSP, FreeMarker ?no_esc
```

A `@RestController` returning JSON is not XSS unless the content type is HTML or the response is
rendered by a client that inserts it unescaped — then the finding is in that client.

## CSRF and CORS

CWE-352, CWE-942 | OWASP A01:2025 Broken Access Control

`csrf().disable()` (`csrf(AbstractHttpConfigurer::disable)`) is a finding only for endpoints that
authenticate by cookie — including a Spring Session cookie — and change state. Bearer-token APIs are not
CSRF targets.

CORS shape is hardening, with one exception that has an exploit: credentials allowed together with an
origin taken from the request — `allowedOriginPatterns("*")` or a filter that echoes `Origin` into
`Access-Control-Allow-Origin` — on cookie-authenticated endpoints. A page on any site then reads the
victim's responses. The Spring version decides what `*` means: Spring 5.3 and later refuse
`allowedOrigins("*")` with `allowCredentials(true)` and offer `allowedOriginPatterns` instead, while
before 5.3 (Spring Boot 2.3 and older) that same pair answers with the request's own `Origin`.

## Authentication and Tokens

CWE-287, CWE-306, CWE-347 | OWASP A07:2025 Authentication Failures

- Spring Security: `permitAll()` or `web.ignoring()` paths broader than intended (`/api/**` instead of
  `/api/public/**`); `mvcMatchers` / `antMatchers` order where an early `permitAll` shadows a later
  rule; a hand-written filter whose skip list matches a prefix an attacker can extend
  (`uri.startsWith("/public")` also matches `/publicAdmin`).
- Hand-written filters: compare the skip list with the controllers it covers. A path the filter skips
  and a controller that trusts the session is a candidate.
- JWT: jjwt `Jwts.parser().parse(token)` also returns tokens without a signature; `parseClaimsJws`
  (`parseSignedClaims` in 0.12) requires one. Auth0 `JWT.decode(token)` and Nimbus `SignedJWT.parse`
  read claims without verifying them. A finding when claims from such a call decide identity or
  access. A signing key hard-coded in source or committed configuration is a finding (CWE-798).
- Remember-me, password reset and invitation tokens: see randomness below.
- An identifier that is enough to receive a token — a device id, an external id, an email — is a
  finding when the same identifier is disclosed somewhere an attacker can read it. Name that second hop.

## Secrets in Source and Configuration

CWE-798, CWE-312 | OWASP A07:2025 Authentication Failures, A02:2025 Security Misconfiguration

Look in `application*.yml`, `application*.properties`, `bootstrap*.yml`, profile files
(`application-prod.yml`), `log4j2.xml` and `logback.xml` appenders with credentials, `Dockerfile` and
`docker-compose*.yaml` `environment:` blocks, CI files, and keystores committed by accident (`*.jks`,
`*.p12`). Search git history for the same files; a secret removed from HEAD can still be live.

A finding needs a live-looking credential: a real host, a non-placeholder password, a key with
provider structure. Empty values, `${DB_PASSWORD}` placeholders and `localhost` development settings
are not findings.

**A default in a placeholder is a secret in source the scanners miss.** Spring resolves
`@Value("${jwt.secret:…}")` and `${DB_PASSWORD:…}` in YAML to the text after the colon when the
property is missing, and that text has no provider prefix. Search for it and read the hits through the
projection only — the commands print file, line and key, never the value:

```bash
rg -n -i -o '\$\{[A-Za-z0-9_.-]*(secret|password|passwd|token|api[-_.]?key|private[-_.]?key|credential)[A-Za-z0-9_.-]*:' -g '*.java' -g '*.kt' -g '*.yml' -g '*.yaml' -g '*.properties' .
rg -n -i '^\s*[A-Za-z0-9_.-]*(secret|password|passwd|token|api[-_.]?key|private[-_.]?key)[A-Za-z0-9_.-]*\s*[:=]\s*[^\s$#{]' \
   -g 'application*' -g 'bootstrap*' . | awk -F: '{ k = $3; sub(/[:=].*/, "", k); print $1 ":" $2 ":" k }'
```

## Spring Boot Actuator

CWE-200, CWE-215 | OWASP A02:2025 Security Misconfiguration

`management.endpoints.web.exposure.include=*` (or a list with `env`, `heapdump`, `configprops`,
`threaddump`, `jolokia`, `logfile`, `httptrace`) on a port the attacker reaches, with no security on
`/actuator/**`, is a finding: `heapdump` contains every secret in memory, and `env` shows values that
older Spring Boot versions do not mask. Check `management.server.port` (a separate internal port is
usually not reachable) and the security rules for the actuator path. `health` and `info` alone are not
findings.

## Cryptography and Randomness

CWE-330, CWE-327, CWE-916, CWE-295 | OWASP A04:2025 Cryptographic Failures

```java
// VULNERABLE for reset tokens, API keys, session ids, invitation codes
String code = String.valueOf(new Random().nextInt(900000) + 100000);
String token = RandomStringUtils.randomAlphanumeric(32);   // java.util.Random inside for most of commons-lang3's history
// SAFE
byte[] b = new byte[32]; new SecureRandom().nextBytes(b);

// VULNERABLE: fast hash for passwords
MessageDigest.getInstance("SHA-256").digest(password.getBytes());
// SAFE: BCryptPasswordEncoder, Argon2PasswordEncoder, Pbkdf2PasswordEncoder

// VULNERABLE: trust everything on a connection to a real remote host
new X509TrustManager() { public void checkServerTrusted(...) {} ... };
conn.setHostnameVerifier((h, s) -> true);
```

Recent commons-lang3 releases changed the generator behind `RandomStringUtils`; which release and to
what was not checked (unverified) — read the version before reporting it. `Cipher.getInstance("AES")`
without a mode is ECB in the default providers. `Random` is fine for
shuffling or sampling. MD5 and SHA-1 for cache keys and checksums are not findings. A timing finding
needs a remote caller who can measure it and a secret worth guessing: `String.equals` or
`Arrays.equals` on an HMAC; `MessageDigest.isEqual` is the constant-time comparison.

## Dependencies With Known Exploits

Read the versions from `pom.xml` / `build.gradle` (and the parent BOM of Spring Boot) when a scanner
is not installed. Report a dependency only with the reachable call the advisory needs:

- **Log4Shell** (CVE-2021-44228): `log4j-core` 2.0-beta9 to 2.14.1, and an attacker-controlled string
  logged through it. Spring Boot logs with Logback unless `spring-boot-starter-log4j2` is used.
- **Spring4Shell** (CVE-2022-22965): Spring Framework 5.3.0-5.3.17 and 5.2.0-5.2.19, JDK 9 or later,
  deployed as a WAR on Tomcat, and a handler binding a POJO from request parameters. On Java 8, or as a
  Spring Boot executable JAR, it is not reachable as published.
- Jackson polymorphic typing, SnakeYAML before 2.0, XStream, commons-collections gadget versions: see
  Deserialization; the version matters only when the vulnerable call exists.

## Information Exposure

CWE-209, CWE-532 | OWASP A02:2025 Security Misconfiguration

Report what leaks a secret: an `@ExceptionHandler` returning `e.toString()` with connection details,
logs holding passwords or tokens, `server.error.include-stacktrace=always` together with an exception
that carries a secret. A stack trace alone is hardening.

## Grep Patterns

Single quotes keep the shell from touching `$` and `"`. These hits are candidates: each still goes
through the source-to-sink check and the refutation pass.

```bash
rg -n '(createQuery|createNativeQuery|prepareStatement|executeQuery|executeUpdate|queryForList|queryForObject|jdbc\w*\.(query|update|execute))\((\s*"[^"]*"\s*\+|\s*String\.format|\s*[a-z]\w*\s*\+)' -g '*.java' .
rg -n -i 'order by[^"]*"\s*\+|JpaSort\.unsafe' -g '*.java' .
rg -n '\$\{' -g '*Mapper.xml' . ; rg -n '@(Select|Update|Delete|Insert)\([^)]*\$\{' -g '*.java' .
rg -n '@Query\((value\s*=\s*)?"[^"]*"\s*\+[^"]*[a-z]\w*' -g '*.java' .
rg -o --no-filename '@ModelAttribute\((value\s*=\s*)?[A-Za-z_.]+\)' -g '*.java' . | sort | uniq -c
rg -n '@SessionAttributes|@RequestParam[^)]*(account|user|owner|tenant|partner|organization)Id|@RequestHeader\("X-(User|Account|Tenant)' -g '*.java' .
rg -n 'BeanUtils\.copyProperties|PropertyUtils\.copyProperties|modelMapper\.map\(|@RequestBody\s+\w*(Entity|User|Account)\b|@InitBinder' -g '*.java' .
rg -n 'ObjectInputStream|\.readObject\(|SerializationUtils\.deserialize|XMLDecoder|XStream|enableDefaultTyping|activateDefaultTyping|LaissezFaireSubTypeValidator|JsonTypeInfo\.Id\.(CLASS|MINIMAL_CLASS)|new Yaml\(' -g '*.java' .
rg -n 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXReader|SAXBuilder|createUnmarshaller' -g '*.java' .
rg -n 'Runtime\.getRuntime\(\)\.exec|new ProcessBuilder|SpelExpressionParser|StandardEvaluationContext|Velocity\.evaluate|new Template\(|buildConstraintViolationWithTemplate\(' -g '*.java' .
rg -n -i "replace(All)?\(\"'\", *\"''\"\)|\w*escape\w*\(" -g '*Repository*.java' -g '*Query*.java' -g '*Dao*.java' .
rg -n '@Cacheable' -g '*Controller*.java' .   # services: read the key of the ones that load by id
rg -n 'Paths\.get\(|Path\.of\(|new File\(|\.resolve\(|getOriginalFilename\(|getNextEntry\(|ZipEntry|getResource\(' -g '*.java' .
rg -n 'new URL\(|openConnection\(|RestTemplate|WebClient|HttpGet\(|HttpPost\(|OkHttpClient|\.getForObject\(|\.exchange\(' -g '*.java' .
rg -n '"redirect:"\s*\+|sendRedirect\(|th:utext|<%=|\?no_esc' -g '*.java' -g '*.html' -g '*.jsp' -g '*.ftl' .
rg -n 'csrf\(\)\.disable|csrf\(\w+::disable|allowedOriginPatterns|allowCredentials|Access-Control-Allow-Origin|permitAll\(\)|\.ignoring\(\)|shouldNotFilter|startsWith\(' -g '*.java' .
rg -n 'Jwts\.parser|\.parse\(|parseClaimsJwt|JWT\.decode\(|SignedJWT\.parse|setSigningKey|signWith' -g '*.java' .
rg -n 'new Random\(|Math\.random\(|RandomStringUtils\.random|MessageDigest\.getInstance\("(MD5|SHA-?1|SHA-256)"|Cipher\.getInstance\("(AES|DES|DESede)"|/ECB/|X509TrustManager|HostnameVerifier|\(h, s\) -> true' -g '*.java' .
rg -n 'management\.endpoints|exposure\.include|include-stacktrace' -g 'application*' -g 'bootstrap*' .
rg -n -A1 '<artifactId>(log4j-core|spring-boot-starter-parent|spring-boot-starter-log4j2|jackson-databind|snakeyaml|xstream|commons-collections)</artifactId>' -g 'pom.xml' .
```

Handlers that take an identifier are listed by the inventory under IDOR, together with their
ownership checks; it replaces a plain grep for `@PathVariable`, which lists every handler. The
`@ModelAttribute` line counts the names used that way: each needs its populating method (see "Where
Identity Comes From"). Run every command with `.` or another path: `rg` with no path searches standard
input when that is a pipe, which is what an assistant's shell often hands it.

## Checklist

1. Where identity comes from: the filter's skip list, what an anonymous request reaches, every `@ModelAttribute` identity covered by its populating method, no caller-supplied account id.
2. Every id, external id or UUID parameter traced to a query; ownership or tenant condition found, or its absence shown by a sibling that has it.
3. No SQL, JPQL or HQL text built with `+` or `String.format`; MyBatis `${}` read; `ORDER BY` from an allow-list or a checked `Sort`.
4. No entity bound from `@RequestBody` or `@ModelAttribute` with sensitive fields; `copyProperties` calls read.
5. No native or polymorphic deserialization of untrusted data; XML factories hardened where XML is untrusted.
6. Process, SpEL, template, file path, URL fetch, redirect and HTML sinks guarded; CSRF and CORS read against how the endpoint authenticates.
7. Secrets: configuration files, placeholder defaults, actuator exposure; dependencies only with a reachable call.

Report only findings where untrusted input reaches the sink, or where a configuration is demonstrably unsafe.
