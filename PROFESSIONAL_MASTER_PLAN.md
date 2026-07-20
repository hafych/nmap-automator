# Recon Operator — professional product master plan

Дата аудита: 2026-07-18  
Целевая версия: 1.12  
Продуктовая граница: профессиональный self-hosted control plane для одного оператора или доверенной команды с API-key isolation. Это не multi-tenant SaaS, не система автоматической эксплуатации и не замена полноценной vulnerability-management/reporting платформы.

## Как вести план

- `[ ]` — не начато.
- `[~]` — выполняется.
- `[x] ~~Пункт~~` — выполнено и проверено.
- Пункт закрывается только после теста или визуальной проверки.
- При регрессии пункт возвращается в работу.

## 0. Аудит и исходная точка

- [x] ~~Обновить GitNexus-индекс до текущего коммита и построить карту архитектуры.~~ 1 299 nodes, 5 223 edges, 56 clusters, 113 flows.
- [x] ~~Пройти реальный browser workflow: auth → discovery scan → job polling → encrypted history → result.~~ Safari/macOS, localhost, 1 host up, encrypted result saved.
- [x] ~~Проверить desktop и узкую компоновку.~~ На 1280 px двухколоночный layout работает; на 736 px результат уходит на несколько экранов вниз, а метрики растягиваются в вертикальный стек.
- [x] ~~Зафиксировать baseline unit quality.~~ 174/174 tests pass; обнаружены повторяющиеся `ResourceWarning` о незакрытых SQLite connections.
- [x] ~~Зафиксировать baseline browser quality.~~ 3/3 Playwright/axe tests pass; serious/critical axe violations — 0; 320 px horizontal overflow — 0.
- [x] ~~Проверить baseline lint/format.~~ Ruff check pass; 45 files formatted.

## 1. Конкурентный аудит и позиционирование

### Что рынок делает хорошо

| Продукт | Сильная сторона | Компромисс относительно Recon Operator |
| --- | --- | --- |
| [Faraday](https://docs.faradaysec.com/Getting-started/) | Единые workspaces, findings из 120+ инструментов, agents/CI/CD, совместная работа | Тяжелее в развёртывании и ориентирован на vulnerability management, а не на компактный локальный scan control loop |
| [Dradis](https://dradis.com/solutions/collaboration.html) | Findings, evidence, QA/review, методологии, client portal и отчётность | Сильнее после сканирования, но не является лёгким локальным scan engine/control plane |
| [DefectDojo](https://docs.defectdojo.com/) | 200+ импортов, дедупликация, triage, remediation, metrics и issue trackers | Требует более сложной модели продуктов/engagements/findings и заметно большей операционной нагрузки |
| [ProjectDiscovery](https://docs.projectdiscovery.io/cloud/introduction) | Continuous asset discovery, актуальные templates, validated findings, retest workflows | Cloud/enterprise exposure-management модель; меньше контроля над полностью локальным и air-gapped контуром |
| [Pentest-Tools.com](https://pentest-tools.com/docs/capabilities/pentest-robots) | Наглядные multi-tool robots, timeline, aggregated reports, scheduling | Платный SaaS, quotas и cloud execution; некоторые цепочки допускают более агрессивные действия, чем review-only позиция проекта |
| [runZero](https://www.runzero.com/platform/) | Persistent asset inventory, correlation, active/passive discovery, OT/IoT visibility | Коммерческая широкая exposure-management платформа, а не компактный open self-hosted operator tool |
| [Greenbone CE](https://greenbone.github.io/docs/latest/background) | Полный vulnerability-management stack, feeds, scan configs и reports | Многосервисная архитектура и более высокая сложность эксплуатации |
| [AutoRecon](https://github.com/Tib3rius/AutoRecon) | Быстрая многопоточная service enumeration в CLI | Нет сопоставимого защищённого dashboard, durable job/schedule model и encrypted result lifecycle |

### Наши подтверждённые плюсы

- Локальный и self-hosted; понятная граница доверия и loopback-by-default.
- Один безопасный job path для UI/API/playbooks, строгая target validation, allowlist, rate/concurrency limits и process-tree cancellation.
- Fernet encryption, atomic files, retention, owner prefixes и audit events.
- Nmap + optional Naabu/RustScan discovery, Kali tool inventory, review-only planner.
- Budgeted AI pack и retest/diff без передачи полного шумного результата.
- Durable jobs/schedules, multi-worker leases, optional Redis coordination.
- Хорошая тестовая база, CSP without `unsafe-inline`, axe/keyboard/320 px regression.

### Наши подтверждённые минусы

- Интерфейс показывает меньше возможностей, чем API: playbooks, posture, audit и полноценный jobs lifecycle скрыты.
- Информационная архитектура — длинная лента карточек; нет ясного рабочего центра «сейчас / история / результат / assurance».
- На узком экране scan form и большие textarea отодвигают результат слишком далеко.
- Результаты в основном представлены как raw text/JSON; нет компактной таблицы hosts/services и понятной next action.
- Preset описан только названием; риск/глубина/что именно запустится не объясняются перед стартом.
- Один global busy-state блокирует несвязанные действия.
- Ошибки и успехи живут в одной строке внутри scan form, плохо сохраняют контекст.
- Нет UI для job cancellation, playbook timeline, posture drift и audit trail.
- Tool inventory занимает много места пустым textarea до загрузки.
- Технический долг: SQLite connections не закрываются после context-manager exit, что видно как `ResourceWarning` в полном test run.

### Дифференциация 1.12

`Recon Operator` должен выигрывать не числом scanner plugins, а самым коротким и безопасным локальным циклом:

`scope → explain → run → observe → compare → plan/retest → audit`.

## 2. Полный список правок

### P0 — целостность и надёжность

- [x] ~~Закрывать каждое SQLite connection после транзакции/чтения без изменения commit/rollback semantics.~~ `_ClosingConnection` сохраняет стандартный transaction exit и гарантирует `close()`.
- [x] ~~Добавить regression test, который доказывает закрытие connection context.~~ Connection после `with` отклоняет SQL как закрытый.
- [x] ~~Устранить `ResourceWarning` в полном unit run.~~ SQLite и subprocess pipes закрываются; 175 tests проходят с `ResourceWarning=error`.
- [x] ~~Не менять API contracts и encrypted artifact format.~~ Полный API/crypto/result regression suite зелёный.

### P0 — новый app shell и информационная архитектура

- [x] ~~Добавить skip-link и семантические landmarks (`header`, `nav`, `main`, named sections).~~
- [x] ~~Сделать компактный professional header: product identity, version/key identity, connection state, global refresh.~~
- [x] ~~Заменить разрозненные pills на осмысленную status/overview strip с API, scanner, active work и stored results.~~
- [x] ~~Добавить локальную section navigation: Operate, Activity, Results, Assurance.~~
- [x] ~~Сохранить все ключевые действия доступными с клавиатуры и без иконок-only.~~
- [x] ~~Перевести feedback в единый persistent toast/live region с success/error/info состояниями.~~

### P0 — scan composer

- [x] ~~Сфокусировать первый экран на target + preset + primary Run action.~~
- [x] ~~Загружать preset/playbook metadata из `/presets`, а не дублировать смысл только в статической разметке.~~
- [x] ~~Показывать описание выбранного preset, профиль, глубину и authorization warning до запуска.~~ Preset и advanced profile синхронизированы.
- [x] ~~Перенести ports/scripts/discovery в progressive disclosure «Advanced options».~~
- [x] ~~Отделить recurring schedule controls от immediate scan.~~
- [x] ~~Отделить import XML от основного scan path.~~
- [x] ~~Заменить global busy-lock на action-scoped состояния и `aria-busy`.~~

### P0 — activity lifecycle

- [x] ~~Объединить immediate jobs и schedules в компактный Activity workspace.~~
- [x] ~~Рендерить queued/running/completed/failed/cancelled/timeout статусы с текстом, а не только цветом.~~
- [x] ~~Добавить cancel для queued/running jobs с подтверждением.~~
- [x] ~~Сохранить cancel scheduled task с понятным объектом действия.~~
- [x] ~~Показать target, profile/preset, age/duration и result availability.~~
- [x] ~~Автообновлять activity только пока есть активная работа; не создавать бесконечный polling loop.~~ Poll завершается на terminal job/playbook status.

### P0 — result workspace

- [x] ~~Сделать history компактным selectable list рядом с текущим результатом на desktop и выше результата на mobile.~~
- [x] ~~Показывать result title, target, profile, timestamp и source filename без технического шума owner prefix в главном заголовке.~~
- [x] ~~Добавить структурированную hosts/services table с host, state, protocol, port, service и version.~~
- [x] ~~Сохранить Summary/JSON/JSONL/Plan/AI/Diff views как доступные tabs.~~ Добавлены keyboard Arrow/Home/End semantics.
- [x] ~~Добавить empty states, которые объясняют следующий шаг.~~
- [x] ~~Сохранить copy current view и добавить явный export/download для text/JSON view без server-side mutation.~~

### P1 — automation и assurance в UI

- [x] ~~Добавить Playbook runner (quick/standard/deep) с описанием фаз до запуска.~~
- [x] ~~Показывать playbook timeline и текущую фазу; поддержать cancel.~~
- [x] ~~Добавить Posture drift evaluator для текущего результата с expected services JSON и понятным summary.~~
- [x] ~~Добавить admin Audit trail viewer с graceful 403 для non-admin key.~~
- [x] ~~Переработать Tool readiness в компактную summary + missing list; не занимать пустым textarea полный экран.~~
- [x] ~~Сохранить AI context copy как вторичное действие.~~

### P1 — visual system и responsive UX

- [x] ~~Ввести согласованные design tokens для light/dark color scheme, spacing, type, radius, focus и status colors.~~
- [x] ~~Добавить native dark mode через `prefers-color-scheme` без пользовательских данных/настроек.~~
- [x] ~~Обеспечить контраст WCAG AA, 44 px touch targets и видимый `:focus-visible`.~~ Axe 4.11 serious/critical = 0.
- [x] ~~Убрать декоративный фон/тени, мешающие плотной operator-информации; сохранить узнаваемый спокойный характер.~~
- [x] ~~На 1280+ px использовать рабочую сетку без чрезмерно узкого result pane.~~
- [x] ~~На 736/390/320 px исключить horizontal overflow и не растягивать каждую метрику в отдельный высокий блок.~~ Safari 736 px visual + Playwright 320 px overflow check.
- [x] ~~Уважать `prefers-reduced-motion`.~~

### P1 — тесты и документация

- [x] ~~Обновить unit DOM assertions под новую семантику и новые панели.~~ Сохранены contract IDs/labels; новые панели входят в DOM regression.
- [x] ~~Расширить Playwright smoke: auth, preset metadata, discovery scan, result selection, job/activity state.~~
- [x] ~~Расширить a11y regression: landmarks, tabs, status messages, 320 px, keyboard path.~~
- [x] ~~Добавить frontend regression для safe DOM rendering пользовательских/API значений.~~ Markup payload остаётся text; `img`/handler не создаются.
- [x] ~~Обновить README screenshots/описание dashboard workflows без изменения security claims.~~ Добавлен пошаговый dashboard workflow без быстро устаревающего binary screenshot.
- [x] ~~Зафиксировать конкурентный аудит и продуктовую границу в release notes/master plan.~~ Этот документ — source of truth.

### Final quality gates

- [x] ~~`ruff check .` и `ruff format --check .`.~~ 45 files clean; `node --check` clean.
- [x] ~~`python -m compileall -q .`.~~
- [x] ~~174+ unit tests без failures и без новых ResourceWarnings.~~ 175/175, `ResourceWarning=error`.
- [x] ~~Playwright smoke + axe: 0 serious/critical violations.~~ 5/5.
- [x] ~~Реальный Safari workflow на desktop и narrow viewport.~~ Auth → discovery → poll → encrypted result на desktop; Activity/Results visual QA на 736 px.
- [x] ~~GitNexus `detect_changes`: только ожидаемые symbols/flows; отдельно описать risk.~~ HIGH, 62 symbols/8 flows: ожидаемые UI `RunScan`, SQLite lifecycle и subprocess cleanup; вне scope flows нет.
- [x] ~~Финальный визуальный аудит; найденные дефекты возвращаются в соответствующий этап.~~ Найдены и исправлены stale-asset cache, header shell, light-theme contrast и preset/profile sync.

Дополнительные release checks: production Bandit — 0 medium/high; `pip-audit` — 0 известных уязвимостей.

## 3. Не делать ради ложного «идеала»

- Не добавлять auto-exploitation, credential attacks или silent aggressive defaults.
- Не превращать single-operator tool в недоделанный multi-tenant SaaS.
- Не добавлять framework/package только ради внешнего вида, если vanilla UI остаётся проще, безопаснее и быстрее.
- Не обещать CVE/vulnerability-management coverage, которой нет у Nmap/review-only planner.
- Не копировать marketing claims конкурентов без технического основания.
