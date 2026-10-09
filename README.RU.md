# security-sieve

Скилл ревью безопасности для Claude Code, Codex и Opencode, который **сообщает
только об уязвимостях, которые атакующий может использовать**.

Работает в два прохода. Сначала собирает кандидатов. Потом проверяет каждого
заново, по отдельности, и пытается доказать, что это не уязвимость. В отчёт
попадают только те уязвимости, которые получили не меньше 8 баллов из 10.

[English version](README.md) · [Как это устроено](docs/guide.ru.md)

## Установка

Linux, macOS:

```bash
git clone https://github.com/vadbosh/security-sieve.git
cd security-sieve
./install.sh
```

Windows:

```powershell
.\install.ps1
```

Установщик копирует скилл в каждого найденного ассистента: `~/.claude`,
`~/.config/opencode`, `~/.codex`. `--dry-run` / `-DryRun` показывает, что будет
записано.

Запуск в ассистенте:

```
/security-sieve                  # текущая ветка относительно merge base
/security-sieve src/api/         # каталог
/security-sieve threat model of the upload service
```

## Зависимости

Обязателен только ассистент. Всё остальное расширяет охват. Скилл запускает то,
что установлено, сам ничего не ставит, а в отчёте пишет, что отработало.

> [!IMPORTANT]
> **Установите `trufflehog`, `gitleaks` и `jq`.** Только через эти два сканера
> ревью видит историю git: ключ, удалённый три коммита назад, по-прежнему лежит
> в каждом клоне. Без них в отчёте будет строка «Secrets in git history: NOT
> scanned». `jq` не даёт значениям секретов попасть к модели; без него
> `trufflehog`, `semgrep` и `trivy` пропускаются.
>
> ```bash
> brew install trufflehog gitleaks jq
> ```
>
> Для других систем: [trufflehog](https://github.com/trufflesecurity/trufflehog/releases),
> [gitleaks](https://github.com/gitleaks/gitleaks/releases),
> [jq](https://jqlang.org/download/).

| Инструмент | Нужен | Что даёт | Без него |
|---|---|---|---|
| Claude Code, Codex или Opencode | да | запускает скилл | — |
| `git` | для режима Diff | merge base, дифф ветки, неотслеживаемые файлы | Режима Diff нет; файлы и каталоги проверяются как обычно |
| `bash` | для сканеров | запускает команды сканеров. На Windows — Git Bash | **Базовая проверка**: модель читает код, сканеры не запускаются. Об этом говорят и установщик, и отчёт |
| [`jq`](https://jqlang.org/download/) | настоятельно рекомендуется | читает их вывод без значений секретов и цитат исходника | Эти три пропускаются; `gitleaks` и `checkov` работают |
| [`trufflehog`](https://github.com/trufflesecurity/trufflehog) | настоятельно рекомендуется | секреты во всех коммитах и в ещё не закоммиченных файлах | Секрет находится, только если он в файле, который читает модель |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | настоятельно рекомендуется | то же по другим правилам; значения скрывает `--redact` | То же, что выше. Историю git покрывает и один из двух |
| [`semgrep`](https://semgrep.dev/docs/getting-started/) | по желанию | паттерны кода для многих языков. Скачивает правила из реестра Semgrep | Модель идёт по коду от точек входа; на большом дереве может пропустить далёкую опасную операцию |
| [`osv-scanner`](https://google.github.io/osv-scanner/) | по желанию | версии зависимостей с известными уязвимостями, по lock-файлам | В режиме Threat model нет списка CVE зависимостей. В режиме Code CVE и так попадает в отчёт, только если уязвимый вызов достижим |
| [`trivy`](https://trivy.dev/) | по желанию | зависимости и ошибки конфигурации IaC | Частично покрывается остальными |
| [`checkov`](https://www.checkov.io/) | по желанию | проверки политик для Terraform, Kubernetes, Dockerfile, CI | Terraform и Kubernetes проверяются только по гайдам |

Значения секретов до модели не доходят: скилл скрывает их в выводе сканеров
секретов и выбрасывает строки исходника, которые цитируют `semgrep` и `trivy`.
Никакая утилита маскирования на вашей машине ему не нужна.

## Что проверяется

| Область | Что ищет | Гайд в `skills/security-sieve/` (`references/`, если каталог не указан) |
|---|---|---|
| Инъекции | SQL, NoSQL, команды ОС, LDAP, шаблоны | `injection.md` |
| Вывод в веб | Отражённый, хранимый и DOM XSS; CSRF | `xss.md`, `csrf.md` |
| Доступ | Авторизация, IDOR, повышение привилегий; сессии, хранение паролей | `authorization.md`, `authentication.md` |
| Данные | Слабая криптография и случайность, утечка секретов, персональные данные, десериализация | `cryptography.md`, `data-protection.md`, `deserialization.md` |
| Файлы и запросы | Обход пути, загрузки, XXE; SSRF | `file-security.md`, `ssrf.md` |
| API и логика | Массовое присваивание, GraphQL, гонки, обход сценария | `api-security.md`, `business-logic.md` |
| Конфигурация | Заголовки, CORS, режим отладки, ошибки, после которых доступ открывается, журналирование | `misconfiguration.md`, `error-handling.md`, `logging.md` |
| Цепочка поставок | Зависимости, сборка, сторонний код без пина | `supply-chain.md` |
| Секреты | Ключи в коде и в истории git, включая удалённые | сканеры + `SKILL.md` |
| ИИ-агенты | Инструменты с побочными эффектами, MCP-серверы и клиенты, скиллы, хуки, prompt injection | `agentic.md`, `modern-threats.md` |
| Python | Django, Flask, FastAPI | `languages/python.md` |
| JavaScript, TypeScript | Node, Express, React, Vue, Next.js | `languages/javascript.md` |
| PHP | Laravel, Symfony, чистый PHP | `languages/php.md` |
| Контейнеры | Dockerfile и запуск | `infrastructure/docker.md` |
| Kubernetes, Helm | Безопасность подов, RBAC, секреты, ingress, чарты | `infrastructure/kubernetes.md` |
| Terraform | IAM, открытость сети, state и секреты в HCL | `infrastructure/terraform.md` |
| CI/CD | GitHub Actions, GitLab CI, Jenkins | `infrastructure/ci-cd.md` |
| Облако | Политики IAM, менеджеры секретов и Vault, TLS между сервисами | `infrastructure/cloud.md` |
| Модель угроз | STRIDE, поверхность атаки, разбор CVE и зависимостей | `threat-modeling.md` |

У каждой находки есть файл и строка, CWE, категория OWASP Top 10:2025, сценарий
атаки, оценка опровержения, исправление и варианты. О чём скилл намеренно не
сообщает — отказ в обслуживании, отсутствие защитных настроек, теоретические
гонки, — написано [в руководстве](docs/guide.ru.md#о-чём-скилл-не-сообщает).

## Лицензия

Apache-2.0 на скилл и наши гайды; справочные материалы из
[getsentry/skills](https://github.com/getsentry/skills) остаются под CC BY-SA 4.0.
Подробности — [docs/guide.ru.md](docs/guide.ru.md#лицензия-и-происхождение),
`NOTICE`.
