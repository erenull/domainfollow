# Alan Adı Takip Sistemi

Bu uygulama, kullanıcıların alan adlarını (domain) takip etmelerini sağlayan bir web uygulamasıdır. Kullanıcılar, alan adlarının kayıt bilgilerini, bitiş tarihlerini ve durumlarını görüntüleyebilir, filtreleyebilir ve yönetebilirler.

## Özellikler

- Kullanıcı kayıt ve giriş sistemi
- Alan adı ekleme, güncelleme ve silme
- Alan adı bilgilerinin otomatik güncellenmesi (WHOIS sorguları ile)
- Alan adlarını filtreleme ve sıralama (bitiş tarihi, kayıt firması, durum)
- Responsive tasarım (mobil uyumlu)

## Kurulum

1. Gerekli paketleri yükleyin:

```bash
pip install -r requirements.txt
```

2. Uygulamayı çalıştırın:

```bash
python app.py
```

3. Tarayıcınızda `http://127.0.0.1:5000` adresine gidin.

## Kullanım

1. Kayıt ol sayfasından bir hesap oluşturun.
2. Giriş yapın.
3. "Alan Adı Ekle" butonuna tıklayarak yeni alan adları ekleyin.
4. Dashboard'da alan adlarınızı görüntüleyin, filtreleme ve sıralama yapın.
5. Alan adlarını güncellemek veya silmek için ilgili butonları kullanın.

## Teknik Detaylar

- **Backend**: Python Flask
- **Veritabanı**: SQLite (SQLAlchemy ORM)
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5
- **Alan Adı Bilgileri**: python-whois kütüphanesi

## Geliştirme

Yeni özellikler eklemek veya mevcut özellikleri geliştirmek için:

1. Projeyi klonlayın
2. Gerekli paketleri yükleyin
3. Değişikliklerinizi yapın
4. Değişikliklerinizi test edin
5. Pull request gönderin

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır.
