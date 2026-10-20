# duckpe.sh

Linux yerel yetki yükseltme (Local Privilege Escalation) kontrollerini tek bir betikle yapan, renkli ve JSON çıktı destekli tarama aracı.

## Kullanım

```bash
chmod +x duckpe.sh
./duckpe.sh
```

Gerçekçi sonuçlar için betiği **root olmayan** bir kullanıcı ile çalıştırın.

### Seçenekler

| Seçenek | Açıklama |
| --- | --- |
| `-v, --verbose` | Tüm SUID/SGID dosyalarını ve ayrıntıları gösterir |
| `--json` | Makine okunabilir JSON çıktısı üretir |
| `--offline` | Exploit-DB/internet sorgusunu kapatır |
| `--no-password` | `sudo -l` için parola sormaz |
| `--fail-on=SEV` | Çıkış eşiği: `warn` (varsayılan), `high`, `crit`, `none` |
| `--only=STEPS` | Yalnızca seçilen adımları çalıştırır (örn. `1,11,15`) |
| `--timeout=SN` | Dış komutlar için zaman aşımı (varsayılan 10 sn) |
| `--selftest` | Yerleşik birim testlerini çalıştırır |
| `-h, --help` | Yardımı gösterir |

### Örnekler

```bash
./duckpe.sh --json > sonuc.json
./duckpe.sh --offline --no-password
./duckpe.sh --only=5,11,12 -v
./duckpe.sh --fail-on=high
```

## Kontrol Adımları

1. Kernel sürümü + Exploit-DB araması
2. Sudo sürümü
3. pkexec sürümü (PwnKit)
4. Sudoers dosyaları
5. Dosya yetenekleri (`getcap`)
6. `/etc/shadow` okunabilirliği
7. `/etc/passwd` okunabilirliği
8. `/etc/passwd` yazılabilirliği
9. `/etc/shadow` yazılabilirliği
10. systemd servisleri
11. SUID/SGID dosyaları + GTFOBins eşleşmeleri
12. `sudo -l` yetkileri
13. Cron işleri ve zamanlayıcılar
14. Dinlenen yerel portlar ve PID'ler
15. Ayrıcalıklı grup üyelikleri
16. Yazılabilir kritik dosya/dizinler
17. `PATH` ve ortam değişkenleri
18. NFS dışa aktarımları ve mount seçenekleri

## Önem Düzeyleri ve Çıkış Kodları

- `KRİTİK`, `YÜKSEK`, `UYARI`, `BULGU`, `OK`, `BİLGİ`
- Çıkış kodu: `0` temiz, `1` uyarı, `2` yüksek, `3` kritik (`--fail-on` ile ayarlanır)

## Notlar

- Tarama sisteme zarar vermez; yalnızca okuma/inceleme yapar.
- `--offline` olmadan Exploit-DB sorgusu için internet erişimi denenir; yoksa tarama devam eder.
- Yalnızca yetkili olduğunuz sistemlerde kullanın.
