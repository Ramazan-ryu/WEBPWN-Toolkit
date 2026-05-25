# 🔐 WebPwn Toolkit v3.1.0 (Elite Evolution)
> **Veb və Mobil Tətbiqlər üçün Penetrasiya Testi (Pentest) Freymvorku**
> Holberton IT School — Kibertəhlükəsizlik üzrə Buraxılış Layihəsi
> Status: ✅ Elite Evolution Tamamlandı

---

## ⚠️ Hüquqi Xəbərdarlıq

**Bu alət yalnız icazə verilmiş təhlükəsizlik testləri üçündür.**
İstifadə etməzdən əvvəl [DISCLAIMER.md](DISCLAIMER.md) faylını oxuyun.
Test etmək üçün yazılı şəkildə açıq icazəniz olmayan sistemlərə qarşı əsla istifadə etməyin.
İcazəsiz istifadə qəti qadağandır və qanunsuzdur.

---

## 📦 Layihə Strukturu

```text
webpwn-toolkit/
├── main.py                        ← CLI giriş nöqtəsi (zəngin interfeys)
├── config.yaml                    ← Alətin konfiqurasiyası
├── requirements.txt               ← Python asılılıqları
├── run.bat                        ← Windows başlatma faylı (UTF-8 dəstəkli)
├── DISCLAIMER.md                  ← Hüquqi xəbərdarlıq
│
├── modules/
│   ├── ai/                        ← Süni intellekt əsaslı Fuzzing & WAF bypass (Generative, RL, NLP)
│   ├── core/                      ← Əsas freymvork (Session, BaseScanner, Deduplicator)
│   ├── mobile/                    ← APK Statik Analiz, Mobil API, Frida İnstrumentasiyası
│   ├── recon/                     ← 7+ Kəşfiyyat (Recon) Modulu (Subdomains, Tech, Headless Crawl, Cloud)
│   ├── reporter/                  ← Senior səviyyəli HTML/PDF Hesabat (Report) generatoru
│   └── web/                       ← 46+ Veb Hücum Modulu, Exploit Engine, Chain Analyzer
│
├── wordlists/
│   ├── directories.txt            ← Qovluq (Directory) bruteforce söz siyahısı
│   ├── subdomains.txt             ← Alt domen (Subdomain) enum söz siyahısı
│   └── payloads/                  ← Qabaqcıl payload-lar (SQLi, XSS, LFI, SSRF, XXE, CMDi, CSRF)
│
├── logs/                          ← Avtomatik yaradılan skan logları
├── reports/                       ← Avtomatik yaradılan HTML/JSON/PDF hesabatları
└── sessions/                      ← Avtomatik yadda saxlanılan sessiya məlumatları (JSON)
```

---

## 🚀 Sürətli Başlanğıc

### 1. Asılılıqları quraşdırın
```bash
pip install -r requirements.txt
```

*(Opsiyonal)* Headless DOM XSS / Crawler üçün Playwright brauzerlərini quraşdırın:
```bash
playwright install
```

### 2. Toolkit-i başladın
```bash
# Windows (məsləhət görülür — UTF-8 kodlaşdırmasını təyin edir)
run.bat

# Və ya birbaşa
python main.py
```

---

## 🗺️ Əsas Menyu və Xüsusiyyətlər

```text
1  ⚙️   Hədəfi Konfiqurasiya Et   — URL, thread (axın) sayı, timeout (zaman aşımı) təyini
2  🔐  Autentifikasiya / Sessiya  — Forma girişi, Bearer token, API key, çərəzlər, proksi
3  🔍  Kəşfiyyat (Recon)          — Alt domenlər, portlar, texnologiya, headless crawler, bulud, GitHub
4  💉  Veb Hücum Modulları        — 46+ zəiflik skaneri + Exploit Engine
5  📱  Mobil Analiz               — APK statik + API təhlükəsizlik testi + Frida
6  📊  Sessiya Xülasəsini Göstər  — Bütün tapıntıların təhlükə səviyyəsinə görə bölgüsü
7  📄  Hesabat Yarat              — Professional Senior-Səviyyə HTML və PDF hesabatları
0  🚪  Çıxış
```

---

## 💉 Veb Hücum Modulları və Mühərriklər (v3.1.0)

v3.1.0 Elite yeniləməsi WebPwn alətini 16 moduldan **46+ Veb Modula** qədər genişləndirir və tamamilə OWASP Top 10 standartlarına uyğunlaşdırır.
Əsas xüsusiyyətlər:

| Kateqoriya | Modullar |
|------------|----------|
| **İnyeksiya (Injection)** | SQLi, Command Injection (CMDi), NoSQLi, LDAP Injection, XPath Injection, CSS Injection, Advanced SSTI, CRLF Injection |
| **XSS və Müştəri Tərəfi** | Reflected XSS, Stored XSS, DOM XSS (Playwright), PostMessage Tester, Prototype Pollution, WebSocket XSS |
| **Autentifikasiya** | Auth Tester, JWT Analyzer, OAuth PKCE Bypass, SAML Injection, 2FA/MFA Bypass |
| **Məntiq (Business Logic)**| Qabaqcıl Business Logic Tester, Rate Limiter Bypass, IDOR Skaneri, API Schema Fuzzer |
| **İnfrastruktur** | SSRF Scanner (AWS/GCP pivot), Cloud Misconfig, Cache Poisoning, HTTP Request Smuggling, Host Header Injection |
| **Qabaqcıl Mühərriklər** | **Exploit Engine** (SQLi/RCE/SSRF/LFI/XSS üçün aktiv istismar), **Chain Analyzer** (Çoxmərhələli hücum zəncirləri), **OOB Tester** (Out-of-Band AST), **Admin Hunter** (Dərin autentifikasiyalı skan) |

---

## 🧠 Süni İntellekt (AI) Mühərriki

WebPwn v3.1.0 aşağıdakı xüsusiyyətlərə malik AI Mühərriki təqdim edir:
1. **Generativ Fuzzing**: LLM əsaslı kontekstə uyğun payload generasiyası.
2. **Reinforcement Learning WAF Bypass**: Payload mutasiyası agenti.
3. **NLP False Positive Filter**: HTTP cavablarının semantik analizi (yanlış müsbət nəticələrin süzülməsi).

---

## 🔐 Autentifikasiyalı Skan

Autentifikasiyanı **bir dəfə** quraşdırın, **bütün** modullar tərəfindən avtomatik istifadə olunsun:
- Forma əsaslı giriş (CSRF tokenlərini avtomatik tutmaqla)
- Bearer token / API Key
- Çiy (Raw) Çərəzlər (Cookies)
- HTTP/HTTPS Proksi (Burp/ZAP inteqrasiyası)

---

## 📄 Senior Səviyyəli Hesabat (Reporting)

WebPwn professional, ekspert səviyyəli penetrasiya testi hesabatlarını (HTML + PDF) avtomatik yaradır:
- **İcraedici Xülasə (Executive Summary)** və Risk İstilik Xəritəsi (Heat-map)
- **CVSS v3.1 Qiymətləndirməsi** və Təhlükə Səviyyəsi Bölgüsü
- Təyin edilmiş texnologiyalar üçün **NVD CVE İnteqrasiyası**
- **Həll Yolları (Remediation)** və Detallı Sübutlar
- Üçüncü tərəf analitika səslərinə (Google Analytics, TikTok və s.) qarşı xüsusi filtrləmə

---

## 📋 Tələblər

```text
Python 3.8+
requests, beautifulsoup4, rich, dnspython, pyyaml, lxml, jinja2,
reportlab, httpx, androguard, playwright, pyotp, websocket-client
```

---

## 🔄 Yeniliklər və Dəyişikliklər (Changelog)

> **Qeyd:** Bu layihədə edilən hər bir yenilik və irəliləyiş dərhal bu bölməyə əlavə ediləcək.

### v3.1.0 (Elite Evolution) — [Cari Versiya]
- **Docker Konteynerizasiyası:** Layihəyə `Dockerfile` və `docker-compose.yml` əlavə edildi.
- **Skan Profilləri:** `profiles/stealth.yaml` və `profiles/aggressive.yaml` yaradıldı (Gizli və aqressiv skan dəstəyi).
- **Məlumat Bazası (SQLite):** Sessiya və skan nəticələri artıq JSON ilə yanaşı mərkəzi `webpwn.db` bazasında saxlanılır.
- **CLI Avtomatlaşdırması:** `main.py` faylına `argparse` dəstəyi gəldi (Məs: `--target`, `--autopilot`).
- **Senior Kod Arxitekturası:** Bütün `base_scanner.py` sistemi `abc.ABC` abstraksiyasına və sərt tipləndirməyə (strict typing) keçirildi. Xəta tutma (logging) qlobal səviyyədə təkmilləşdirildi.
- **Kod Formatlanması (PEP8):** Bütün 85+ Python faylı `black` ilə beynəlxalq standartlara formatlandı. Qoruma məqsədilə `pytest` və `.pre-commit-config.yaml` əlavə edildi.

---

*Holberton IT School üçün ❤️ ilə qurulub — Kibertəhlükəsizlik üzrə Buraxılış Layihəsi*
