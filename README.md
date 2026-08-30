# ACL Generator - Kurumsal Ağ ACL Yapılandırma, Güvenlik Analiz ve Simülasyon Konsolu

> **Ağ Mühendisleri, Siber Güvenlik Uzmanları ve Ağ Öğrencileri İçin Gelişmiş ACL Oluşturma, Analiz ve Paket Simülasyon Konsolu**

<img width="1916" height="927" alt="image" src="https://github.com/user-attachments/assets/d845ec33-db54-4b75-98d0-3e099f469b14" />

---

## Ne İşe Yarar ve Hangi Sorunları Çözer?

Cisco, Juniper veya Huawei ağ cihazlarında Erişim Kontrol Listeleri (ACL) oluşturmak manuel yapıldığında zaman alıcı, karmaşık ve hataya açıktır. 

`ACL Generator`, ağ mühendislerinin, güvenlik uzmanlarının ve öğrencilerin günlük işlerinde karşılaştığı şu temel sorunları çözer:

1. **Karmaşık Wildcard Maske Hesaplamalarından Kurtarır:**  
   Alt ağ maskelerinden (`255.255.240.0`) Wildcard maskelere (`0.0.15.255`) veya CIDR notasyonuna (`/24`) dönüşümleri anında bit düzeyinde doğru hesaplar.
2. **Gölgede Kalan (Shadowed) Hatalı Kuralları Engeller:**  
   Üst sırada yazılan geniş bir kuralın (`permit ip any any`), alttaki kuralları etkisiz kılmasını otomatik analiz eder ve güvenlik zafiyeti oluşmasını engeller.
3. **Canlı Trafik Paket Simülasyonu Sağlar:**  
   Yazdığınız kuralları router veya firewall cihazına yüklemeden önce, test paketleri (`Kaynak IP`, `Hedef IP`, `Port`) göndererek trafiğin geçeceğini mi (`PERMIT`) yoksa engelleneceğini mi (`DENY`) canlı simüle eder.
4. **Açıklanabilir Politika Teşhisi (Explainable Policy Diagnostics):**  
   Paket simülasyonunda alt sıradaki çatışan kuralların neden çalışmadığını ve hangi kural tarafından engellendiğini adım adım teşhis eder.
5. **Tersine CLI Ayrıştırma (Reverse ACL Parser):**  
   Var olan ham Cisco CLI komut çıktılarınızı yapıştırarak tek tıkla görsel kural tablosuna dönüştürür ve düzenlemenizi sağlar.
6. **Çoklu Cihaz Desteği (Multi-Vendor):**  
   Tek tıkla **Cisco IOS**, **Juniper JunOS** ve **Huawei VRP** donanımları için kopyalamaya hazır CLI yapılandırma kodları üretir.
7. **Eğitici ve Doğru Yerleşim Rehberi:**  
   Standard ve Extended ACL kurallarının kaynağa mı (Source) yoksa hedefe mi (Destination) uygulanması gerektiğini ve `Implicit Deny` mantığını görsel Syslog uyarılarıyla öğretir.

---

## Öne Çıkan Özellikler

- **100vh Tam Ekran NOC Konsolu:** Sayfa kaydırma çubuğu olmadan, %100 ekrana oturan koyu tema (`#0b0f19`) kurumsal mühendislik arayüzü.
- **Canlı Paket Simülatörü:** Kaynak/Hedef IP ve port bilgilerini girerek TCAM donanım eşleşmesini anında test etme.
- **💡 Açıklanabilir Teşhisi (Explainable Diagnostics):** Paket engellendiğinde veya izin verildiğinde, kararın hangi kural nedeniyle alındığını ve alt sıradaki kuralların neden elendiğini açıklar.
- **🛡️ Statik Güvenlik Risk Analizörü:** SSH/Telnet (`TCP/22`, `TCP/23`) üzerinden Yönetim Ağına (`10.20.40.0/24`) doğrudan erişim veren riskli kuralları otomatik tespit eder.
- **Tersine Komut Ayrıştırıcı:** Ham Cisco CLI çıktılarını yapıştırıp kural tablosuna aktarma.
- **Çoklu Dil Desteği:** Tek tıkla Türkçe (`TR`) ve İngilizce (`EN`) arasında kesintisiz geçiş.

---

## İnternet Üzerinden Doğrudan Kullanım (GitHub Pages)

Uygulamayı bilgisayarınıza indirmeden, doğrudan internet tarayıcınızda kullanmak için canlı adrese tıklayabilirsiniz:

👉 **[https://furrkanyasar.github.io/acl-generator/](https://furrkanyasar.github.io/acl-generator/)**

---

## Bilgisayarınızda Nasıl Çalıştırırsınız?

Uygulamayı kendi bilgisayarınızda yerel olarak çalıştırmak isterseniz:

### Gerekli Gereksinimler
- Herhangi bir modern internet tarayıcısı (Google Chrome, Microsoft Edge, Mozilla Firefox vb.).
- Python 3.x (Yerel sunucu çalıştırmak için).
- Node.js (Otomatik test yürütücüsünü çalıştırmak için).

### Adım Adım Kurulum ve Çalıştırma

1. **Projeyi İndirin veya Klonlayın:**
   ```bash
   git clone https://github.com/furrkanyasar/acl-generator.git
   cd acl-generator
   ```

2. **Yerel Sunucuyu Başlatın:**
   Klasör içindeki yerel Python sunucusunu çalıştırın:
   ```bash
   python server.py
   ```

3. **Tarayıcıda Açın:**
   İnternet tarayıcınızda şu adrese gidin:
   ```text
   http://localhost:8000
   ```

---

## Proje Dosya Yapısı

```text
acl-generator/
├── index.html                  # Ana HTML giriş dosyası
├── server.py                    # Yerel Python HTTP sunucusu
├── run_all_release_tests.js     # Master entegrasyon ve doğrulama test suite
├── test_runner_node.js         # Node.js uçtan uca test yürütücüsü
├── README.md                   # Proje dokümantasyonu
└── src/
    ├── app.js                  # Uygulama durum yöneticisi ve arayüz oluşturucu
    ├── styles.css              # NOC koyu tema CSS ve 100vh ızgara düzeni
    ├── components/
    │   ├── Header.js               # 46px navigasyon çubuğu ve kontrol butonları
    │   ├── ACLSettings.js          # ACL tipi, adı ve arabirim ayarları
    │   ├── RuleForm.js             # ACE kural oluşturma formu
    │   ├── RuleTable.js            # Monospaced kural tampon tablosu ve aksiyonlar
    │   ├── PreviewPanel.js         # Terminal CLI kod önizleme penceresi
    │   ├── TrafficSimulator.js     # Canlı paket eşleşme ve simülasyon paneli
    │   ├── EducationalPanel.js     # Syslog ve tanı konsolu
    │   ├── ImportModal.js          # Ham Cisco CLI içe aktarma penceresi
    │   └── TemplatesModal.js       # Şablon seçim penceresi
    └── core/
        ├── types.js                # Temel veri yapıları ve sabitler
        ├── wildcard.js             # Bit bazlı maske ve CIDR hesaplayıcı
        ├── analyzer.js             # Shadowed kural ve güvenlik analizörü
        ├── exporter.js             # Çoklu cihaz CLI script üreticisi
        ├── parser.js               # Tersine Cisco CLI ayrıştırıcı motoru
        ├── simulator.js            # Paket eşleşme simülasyon motoru
        ├── i18n.js                 # Çoklu dil (TR/EN) sözlüğü
        └── generators/
            ├── cisco.js            # Cisco IOS CLI kod üreticisi
            ├── juniper.js          # Juniper JunOS script üreticisi
            └── huawei.js           # Huawei VRP script üreticisi
```

---

## Otomatik Testleri Çalıştırma

Projedeki ağ matematiği, CIDR kapsama cebiri ve kural eşleşme motorunu uçtan uca doğrulamak için Node.js master test yürütücüsünü çalıştırabilirsiniz:

```bash
node run_all_release_tests.js
```

Ayrıca uçtan uca düğüm testlerini çalıştırmak için:
```bash
node test_runner_node.js
```

Beklenen çıktı:
```text
==================================================================
  FINAL RELEASE GATE SCORECARD REPORT
==================================================================
PRODUCTION IMPORT:               PASS
INTEGRATION:                     44/44 PASS
NEGATIVE:                        17/17 PASS
PROPERTY:                        1000/1000 PASS
MUTATION:                        15/15 KILLED (%100.0)
FUZZ:                            50/50 PASS
PARSER E2E:                      10/10 PASS
SIMULATOR DIFFERENTIAL:          21/21 PASS
SECURITY:                        11/11 PASS
DISABLED INDEX:                  5/5 PASS
HOST /32:                        3/3 PASS
PORT INTERVAL:                   15/15 PASS
PROTOCOL:                        3/3 PASS
ICMP:                            2/2 PASS
RUNNER SELF TEST:                PASS

==================================================================
  FINAL DECISION: PASS
==================================================================
```

---

## Lisans

Bu proje **GNU General Public License v3.0 (GPL-3.0)** ile lisanslanmıştır. Eğitim ve kurumsal ağ mühendisliği kullanımı için tamamen açık kaynaklıdır.

---

<details>
<summary><b>English Documentation (Click to expand)</b></summary>

<br>

# ACL Generator - Enterprise Network Access Control List Builder & Security Console

> **Advanced ACL Construction, Analysis, and Packet Simulation Console for Network Engineers, Cybersecurity Specialists, and Network Students**

<img width="1916" height="927" alt="image" src="https://github.com/user-attachments/assets/d845ec33-db54-4b75-98d0-3e099f469b14" />

---

### What Does It Do and What Problems Does It Solve?

Building Access Control Lists (ACLs) manually on Cisco, Juniper, or Huawei network equipment is time-consuming, complex, and prone to human error.

`ACL Generator` solves the following core problems faced daily by network engineers, security specialists, and students:

1. **Eliminates Complex Wildcard Mask Calculations:**  
   Instantly calculates accurate bitwise conversions from Subnet Masks (`255.255.240.0`) to Wildcard Masks (`0.0.15.255`) and CIDR notation (`/24`).
2. **Prevents Shadowed Security Rules:**  
   Automatically analyzes if a broader rule written above (e.g. `permit ip any any`) invalidates subsequent rules, preventing security vulnerabilities.
3. **Provides Real-Time Traffic Packet Simulation:**  
   Simulates test packets (`Src IP`, `Dst IP`, `Protocol`, `Port`) live before deploying rules to routers or firewalls to verify whether traffic will be `PERMITTED` or `DENIED`.
4. **Explainable Policy Diagnostics:**  
   Step-by-step diagnostic breakdown explaining why lower conflicting ACE rules were bypassed due to first-match evaluation logic.
5. **Reverse CLI Parser:**  
   Converts existing raw Cisco CLI command outputs into an interactive visual rule table with a single click.
6. **Multi-Vendor Equipment Support:**  
   Generates copy-paste-ready CLI configuration scripts for **Cisco IOS**, **Juniper JunOS**, and **Huawei VRP** equipment in one click.
7. **Educational and Accurate Placement Guidance:**  
   Teaches proper placement rules (Standard ACL near Destination, Extended ACL near Source) and `Implicit Deny` mechanics via visual Syslog alerts.

---

### Key Features

- **100vh Full-Screen NOC Console:** Enterprise engineering dashboard with a dark slate theme (`#0b0f19`) fitting 100% of the screen without page scrollbars.
- **Live Packet Simulator:** Test TCAM hardware matching instantly by entering Source/Destination IP and port parameters.
- **💡 Explainable Diagnostics:** Visual breakdown explaining the decision logic behind matching rules and overridden lower ACEs.
- **🛡️ Static Security Risk Engine:** Automatically flags high-risk permits granting administrative SSH/Telnet access (`TCP/22`, `TCP/23`) to Management Subnets (`10.20.40.0/24`).
- **Reverse Command Parser:** Import raw Cisco CLI outputs directly into active rule buffers.
- **Multi-Language Engine:** Seamless toggle between Turkish (`TR`) and English (`EN`) with a single click.

---

### Online Instant Usage (GitHub Pages)

Click below to use the application directly in your browser:

👉 **[https://furrkanyasar.github.io/acl-generator/](https://furrkanyasar.github.io/acl-generator/)**

---

### How to Run Locally on Your Computer

If you want to run the application locally on your computer:

#### Prerequisites
- Any modern web browser (Google Chrome, Microsoft Edge, Mozilla Firefox, etc.).
- Python 3.x (to run local dev server).
- Node.js (to run master test suite).

#### Step-by-Step Installation and Usage

1. **Clone or Download Project:**
   ```bash
   git clone https://github.com/furrkanyasar/acl-generator.git
   cd acl-generator
   ```

2. **Start Local Server:**
   Run the local Python server inside the folder:
   ```bash
   python server.py
   ```

3. **Open in Browser:**
   Navigate to the following address in your browser:
   ```text
   http://localhost:8000
   ```

---

### Automated Unit Testing

To run the full end-to-end master test suite (interval algebra, property tests, parser E2E, and adversarial mutations):

```bash
node run_all_release_tests.js
```

To run end-to-end node suite tests:
```bash
node test_runner_node.js
```

Expected output:
```text
==================================================================
  FINAL RELEASE GATE SCORECARD REPORT
==================================================================
PRODUCTION IMPORT:               PASS
INTEGRATION:                     44/44 PASS
NEGATIVE:                        17/17 PASS
PROPERTY:                        1000/1000 PASS
MUTATION:                        15/15 KILLED (%100.0)
FUZZ:                            50/50 PASS
PARSER E2E:                      10/10 PASS
SIMULATOR DIFFERENTIAL:          21/21 PASS
SECURITY:                        11/11 PASS
DISABLED INDEX:                  5/5 PASS
HOST /32:                        3/3 PASS
PORT INTERVAL:                   15/15 PASS
PROTOCOL:                        3/3 PASS
ICMP:                            2/2 PASS
RUNNER SELF TEST:                PASS

==================================================================
  FINAL DECISION: PASS
==================================================================
```

---

### License

Distributed under the **GNU General Public License v3.0 (GPL-3.0)**. Open-source for educational and professional network engineering use.

</details>
