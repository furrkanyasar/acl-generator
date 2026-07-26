# ACL Generator - Kurumsal Ağ ACL Yapılandırma, Güvenlik Analiz ve Simülasyon Konsolu

> **Ağ Mühendisleri, Siber Güvenlik Uzmanları ve Ağ Öğrencileri İçin Gelişmiş ACL Oluşturma, Analiz ve Paket Simülasyon Konsolu**

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
4. **Tersine CLI Ayrıştırma (Reverse ACL Parser):**  
   Var olan ham Cisco CLI komut çıktılarınızı yapıştırarak tek tıkla görsel kural tablosuna dönüştürür ve düzenlemenizi sağlar.
5. **Çoklu Cihaz Desteği (Multi-Vendor):**  
   Tek tıkla **Cisco IOS**, **Juniper JunOS** ve **Huawei VRP** donanımları için kopyalamaya hazır CLI yapılandırma kodları üretir.
6. **Eğitici ve Doğru Yerleşim Rehberi:**  
   Standard ve Extended ACL kurallarının kaynağa mı (Source) yoksa hedefe mi (Destination) uygulanması gerektiğini ve `Implicit Deny` mantığını görsel Syslog uyarılarıyla öğretir.

---

## Öne Çıkan Özellikler

- **100vh Tam Ekran NOC Konsolu:** Sayfa kaydırma çubuğu olmadan, %100 ekrana oturan koyu tema (`#0b0f19`) kurumsal mühendislik arayüzü.
- **Canlı Paket Simülatörü:** Kaynak/Hedef IP ve port bilgilerini girerek TCAM donanım eşleşmesini anında test etme.
- **Tersine Komut Ayrıştırıcı:** Ham Cisco CLI çıktılarını yapıştırıp kural tablosuna aktarma.
- **Çoklu Dil Desteği:** Tek tıkla Türkçe (`TR`) ve İngilizce (`EN`) arasında kesintisiz geçiş.

---

## İnternet Üzerinden Doğrudan Kullanım (GitHub Pages)

Uygulamayı bilgisayarınıza indirmeden, doğrudan internet tarayıcınızda kullanmak için canlı adresi ziyaret edebilirsiniz:

```text
https://furrkanyasar.github.io/acl-generator/
```

---

## Bilgisayarınızda Nasıl Çalıştırırsınız?

Uygulamayı kendi bilgisayarınızda yerel olarak çalıştırmak isterseniz:

### Gerekli Gereksinimler
- Herhangi bir modern internet tarayıcısı (Google Chrome, Microsoft Edge, Mozilla Firefox vb.).
- Python 3.x (Yerel sunucu çalıştırmak için).

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
├── index.html              # Ana HTML giriş dosyası
├── server.py                # Yerel Python HTTP sunucusu
├── test_runner.py          # Otomatik birim test yürütücüsü
├── README.md               # Proje dokümantasyonu
└── src/
    ├── app.js              # Uygulama durum yöneticisi ve arayüz oluşturucu
    ├── styles.css          # NOC koyu tema CSS ve 100vh ızgara düzeni
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

Projedeki ağ matematiği ve kural eşleşme motorunu test etmek için terminalde şu komutu çalıştırabilirsiniz:

```bash
python test_runner.py
```

Beklenen çıktı:
```text
..
----------------------------------------------------------------------
Ran 2 tests in 0.000s

OK
```

---

## Lisans

Bu proje **MIT Lisansı** ile lisanslanmıştır. Eğitim ve kurumsal ağ mühendisliği kullanımı için tamamen açık kaynaklıdır.

---

<details>
<summary><b>English Documentation (Click to expand)</b></summary>

<br>

# ACL Generator - Enterprise Network Access Control List Builder & Security Console

> **Advanced ACL Construction, Analysis, and Packet Simulation Console for Network Engineers, Cybersecurity Specialists, and Network Students**

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
4. **Reverse CLI Parser:**  
   Converts existing raw Cisco CLI command outputs into an interactive visual rule table with a single click.
5. **Multi-Vendor Equipment Support:**  
   Generates copy-paste-ready CLI configuration scripts for **Cisco IOS**, **Juniper JunOS**, and **Huawei VRP** equipment in one click.
6. **Educational and Accurate Placement Guidance:**  
   Teaches proper placement rules (Standard ACL near Destination, Extended ACL near Source) and `Implicit Deny` mechanics via visual Syslog alerts.

---

### Key Features

- **100vh Full-Screen NOC Console:** Enterprise engineering dashboard with a dark slate theme (`#0b0f19`) fitting 100% of the screen without page scrollbars.
- **Live Packet Simulator:** Test TCAM hardware matching instantly by entering Source/Destination IP and port parameters.
- **Reverse Command Parser:** Import raw Cisco CLI outputs directly into active rule buffers.
- **Multi-Language Engine:** Seamless toggle between Turkish (`TR`) and English (`EN`) with a single click.

---

### Online Instant Usage (GitHub Pages)

You can use the application directly in your browser without downloading:

```text
https://furrkanyasar.github.io/acl-generator/
```

---

### How to Run Locally on Your Computer

If you want to run the application locally on your computer:

#### Prerequisites
- Any modern web browser (Google Chrome, Microsoft Edge, Mozilla Firefox, etc.).
- Python 3.x (to run local dev server).

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

To test the network math and rule matching engine:

```bash
python test_runner.py
```

Expected output:
```text
..
----------------------------------------------------------------------
Ran 2 tests in 0.000s

OK
```

---

### License

Distributed under the **MIT License**. Open-source for educational and professional network engineering use.

</details>
