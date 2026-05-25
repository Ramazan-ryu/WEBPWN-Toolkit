# WebPwn Toolkit — Peşəkar Audit və İstismar Bələdçisi

Yaradılıb: 25 May 2026

## İcraçı Xülasəsi

Bu sənəd WebPwn Toolkit üçün əməliyyat səviyyəsində, istifadə etməyə hazır və təlimatlı bir bələdçidir. İçərisində:
- Son düzəlişlərin texniki auditi,
- Dəqiq API müqavilələri və nümunə payload-lar,
- Frontend inteqrasiya qeydləri,
- `AdminHunter` modulunun davranışı və nümunə tapıntıları,
- Tövsiyə olunan konfiqurasiya parçaları və runbook-lar,
- Sənədi PDF və ya slayd dəstinə çevirmək üçün seçimlər.

Qeyd: Mətn praktikdir — kopyala-yapışdır əmrləri, JSON nümunələri və test tövsiyələri daxildir ki, komandaya sürətlə ötürə və ya təqdimat üçün istifadə edə biləsiniz.

---

## 1) Qısa Quraşdırma (Developer)

Tələb olunanlar:
- Python 3.10+ (bu workspace Python 3.14 ilə sınaqdan keçirildi)
- `pip`
- Opsiyonel: `reportlab`, `python-pptx`, `pandoc` slayd/PDF ixracı üçün

Asılılıqları quraşdırın:

```bash
pip install -r requirements.txt
```

Local serveri işə salın:

```bash
# Windows
run.bat
# və ya
python web_server.py
```

Brauzerdə UI-ı açın: http://localhost:5000 (serverdə çap olunan URL-i yoxlayın).

---

## 2) API Referansı (Dəqiq Müqavilə)

### GET /api/modules

Təsvir: UI üçün mövcud modulları qaytarır. `web` modulları sıraya salınmış massiv kimi gəlir ki, UI backend sırasını saxlasın.

Nümunə cavab (v3 formatı):

```json
{
  "recon": {
    "1": "Subdomain Enumeration",
    "2": "Port Scanner",
    "3": "Technology Fingerprinting"
  },
  "web": [
    {"display":"1","key":"1","name":"SQL Injection"},
    {"display":"2","key":"2","name":"XSS Scanner"},
    {"display":"3","key":"3","name":"Directory Bruteforce"}
  ],
  "mobile": {
    "1": "APK Static Analysis",
    "2": "Mobile API Tester",
    "3": "Dynamic Instrumentation (Frida)"
  }
}
```

Qeydlər:
- `web` array-dir: hər obyekt `display` (UI üçün nömrə), `key` (backend tərəfindən istifadə olunan tapşırıq açarı) və `name` (insan-oxunaqlı etiket) sahələrinə malikdir.
- UI skan sorğuları göndərərkən həmişə `key` istifadə etməlidir; `display` yalnız vizual məqsədlər üçündür.


### POST /api/configure

İstək bədəni nümunəsi:
```json
{ "sid": "default", "target": "https://example.com", "threads": 10, "timeout": 10 }
```

Cavab nümunəsi:
```json
{ "ok": true, "target": "https://example.com", "domain": "example.com" }
```

Məqsəd: scan zamanı istifadə olunacaq yaddaşdaxili sessiyanı yaratmaq və ya yeniləmək.


### GET /api/session?sid=default

Cavab strukturu:

```json
{
  "target": "https://example.com",
  "domain": "example.com",
  "findings_count": 3,
  "findings": [ /* finding obyektləri massiv */ ]
}
```


### POST /api/generate_report

İstək: `{"sid":"default"}`

Davranış: `modules.reporter.html_report.ReportGenerator(sess).generate(name)` çağırır və yaradılan hesabat yolunu qaytarır. Tapıntı yoxdursa 400 qaytarır.

---

## 3) Frontend İnteqrasiya Qeydləri (Əməli)

Fayl: `webui/app.js`

Əsas məqamlar:
- `loadModules()` `/api/modules`-i çağırır və `buildModuleList()`-ə göndərir.
- `buildModuleList()` ya object, ya da array qəbul edir.
- Əgər `mods` array-dirsə, hər giriş `key` sahəsinə malik olmalıdır; bu `element.dataset.key` kimi istifadə olunur.
- `startScan()` seçilmiş elementləri `getSelected(type)` ilə toplayır və SocketIO üzərindən `start_scan` hadisəsi yollayır: `module_type`, `selected`, `session_sid` daxil.

Tövsiyə: backend `key` sahəsini etibarlı ünvan kimi saxlamalıdır; frontend həmişə `key` göndərsin.

Scan axını nümunəsi (developer konsolundan):

```js
// Brauzer konsolunda ilk iki web modulunu scan başlatmaq
const selected = ['1','2'];
io_socket.emit('start_scan', { module_type: 'web', selected, session_sid: 'default' });
```

---

## 4) Admin Hunter — Davranış, Heuristikalar və Nümunə Tapıntılar

`AdminHunter` modulu dörd mərhələdən ibarətdir: Giriş yoxlaması, login bruteforce, autentifikasiyalı dərin skan və passiv yoxlamalar.

Əməli prinsip (son düzəlişlərdən sonra):
- Passiv leak yoxlamaları əgər səhifədə login formu varsa ATLAYIR — bu, auth ilə qorunan login səhifələrində yanlış-müsbət tapıntılardan qoruyur (məs. OWASP Juice Shop admin login).
- Əgər səhifə HTTP 200 ilə açıqdır və login formu yoxdur, lakin dashboard göstəriciləri (`dashboard`, `logout` və s.) varsa, bu, açıq admin paneli kimi qiymətləndirilir (yüksək prioritet).

Default cred tapıldıqda nümunə finding:

```json
{
  "url": "https://target.example.com/admin/login",
  "type": "Admin Panel — Default Credentials",
  "severity": "critical",
  "detail": "Successfully logged into admin panel with admin:admin",
  "evidence": "Credentials: admin:admin | URL: https://target.example.com/admin/login",
  "owasp": "A07:2021 – Identification and Authentication Failures",
  "cvss": 9.8,
  "remediation": "Change default credentials and enable MFA."
}
```

Passiv info-leak nümunəsi (yalnız login formu yoxdursa):

```json
{
  "url": "https://target.example.com/admin/debug",
  "type": "Admin Page Info Leak — Stack trace leak",
  "severity": "high",
  "detail": "Stack trace strings found in admin debug page response",
  "evidence": "Pattern matched: stack trace",
  "owasp": "A05:2021 – Security Misconfiguration",
  "cvss": 7.5
}
```

Pentester üçün əməli qeydlər:
- Juice Shop və s. məqsədli zəif tətbiqlərdə admin login səhifələri ola bilər — login formunu avtomatik zəiflik kimi qiymətləndirməyin.
- Əsas diqqət: açıq dashboardlar, default parollar, autentifikasiya tələb etməyən səhifələrdə həssas məlumat, və admin API-lərdə OBJEKT SƏVİYYƏSİ İCAZƏSİ yoxlamaları (IDOR).

---

## 5) Runbook və Nümunə Əmrlər (Demo üçün)

1) Hədəfi konfiqurasiya edin və qısa recon + web scan işə salın:

```bash
# Sessiya qur
curl -X POST -H "Content-Type: application/json" http://localhost:5000/api/configure -d '{"sid":"demo","target":"http://juice-shop:3000","threads":8,"timeout":8}'

# Web scan UI və ya socket vasitəsilə başlayır; avtomatlaşdırma üçün headless skript istifadə edin.
```

2) Skan sonrası tapıntıları əldə edin:

```bash
curl "http://localhost:5000/api/session?sid=demo"
```

3) Server tərəfdə PDF hesabatı yaradın (əgər tapıntılar varsa):

```bash
curl -X POST -H "Content-Type: application/json" http://localhost:5000/api/generate_report -d '{"sid":"demo"}'
```

---

## 6) Hesabat Formatı və Nümunə Şema

Tövsiyə olunan finding JSON sxemi (kanonik):

```json
{
  "url": "string",
  "type": "string",
  "severity": "info|low|medium|high|critical",
  "detail": "detailed human-readable description",
  "evidence": "short evidence snippet",
  "owasp": "OWASP mapping",
  "cvss": 0.0,
  "remediation": "human readable remediation steps"
}
```

Bu sxemi `modules/*` üçün standart kimi tətbiq edin — reporter və UI daha sadə və ardıcıl olar.

---

## 7) Tövsiyə Olunan Əlavələr (Senior səviyyəli)

- `modules/reporter/generator.py` əlavə edin; bu modul sessiya dict qəbul edib həm HTML/PDF, həm də Markdown və PPTX yaratsın. Mövcud `ReportGenerator`-ı test edilə bilən API halına gətirin.
- Unit testlər əlavə edin:
  - `test_api_modules_ordering` — `GET /api/modules`-in `WEB_ATTACK_TASK_ORDER` ilə uyğun sırada gəldiyini yoxlayın.
  - `test_adminhunter_passive_skip` — mock HTTP cavabında login formu olduqda passiv yoxlamaların atıldığını doğrulayın.
- CI: PR-lərdə `pytest` işlətsin və release pipeline PDF artefaktı yaratsın.

---

## 8) İxrac Seçimləri: MD → PDF / Slaydlar

Seçim A — mövcud `reportlab` skripti (server tərəfi): artıq `reportlab` ilə PDF yaradıla bilir.

Seçim B — Markdown-dan `pandoc` ilə çevirmək:

```bash
# Pandoc tələb olunur
pandoc reports/complete_toolkit_presentation.md -o reports/complete_toolkit_presentation.pdf --pdf-engine=xelatex
```

Seçim C — PPTX yaratmaq (təqdimatlar üçün tövsiyə olunur): `python-pptx` quraşdırın və bölmələri slaydlara çevirən generator yazın.

---

## 9) Əlavə Fayllar (Nümunələr)
- `reports/sample_findings.json` — nümunə tapıntılar (repo-da var)
- `sessions/session_demo.json` — nümunə sessiya çıxarışı (opsional)

---

## 10) Gələcək Addımlar (Mənim tərəfimdən icra oluna biləcək)
- Bu sənədin PDF versiyasını yaratmaq (`reportlab` və ya `pandoc` ilə).
- `.pptx` slayd dəsti yaratmaq (`python-pptx` ilə).
- Unit test və CI düzəlişlərini repo-ya əlavə etmək.

---

Hazırlayan: internal audit skripti — istəsəniz bunu formal `modules/reporter` generatoruna çevirə bilərəm.
