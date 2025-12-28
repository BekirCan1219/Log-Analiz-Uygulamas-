LogWatch – Merkezi Log Analiz ve Alarm Sistemi

LogWatch; Flask tabanlı, MSSQL + SQLAlchemy kullanan bir log ingest, kural motoru ve alarm izleme uygulamasıdır.
Sistem; farklı log kaynaklarından gelen verileri merkezi olarak toplar, tanımlı kurallara göre analiz eder ve oluşan alarmları dashboard üzerinden read-only olarak görüntüler.

Bu projede admin / role / ack / close yönetimi bilinçli olarak kaldırılmıştır.
Tüm alarmlar yalnızca görüntülenir; sistem SOC-style analiz ve drilldown odaklıdır.

Özellikler
- Log ingest (JSON / text)
- Rule engine (count, distinct, status spike, pattern match)
- Deduplication ve cooldown
- Read-only alert izleme
- Drilldown event inceleme
- Dashboard (time-series, top services, top IPs)

Mimari
Log Sources -> Ingest API -> LogEvent (MSSQL) -> Rule Engine -> Alert -> Dashboard

Kimlik Doğrulama
Basit demo login sistemi vardır.
Admin rolü yoktur.
Ack / close / note / role yönetimi bulunmaz.

Örnek API
GET /api/alerts?status=open
GET /api/alerts/{id}
GET /api/alerts/{id}/events
POST /api/alerts/run

Proje Yapısı
app/
 controllers/
 models/
 services/
 templates/

Tasarım Kararları
Admin yönetimi kaldırılmıştır.
Uygulama analiz ve gözlem odaklıdır.
SOC / SIEM mantığına uygundur.

Geliştirici
Bekir Can İmamoğlu
Karadeniz Teknik Üniversitesi
Yazılım Mühendisliği

