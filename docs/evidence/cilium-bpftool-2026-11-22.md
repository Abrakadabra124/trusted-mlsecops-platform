# Происхождение статических библиотек в Cilium bpftool

Для `/usr/local/bin/bpftool` из агента Cilium 1.20.5 повторно прочитан файл из публичного OCI-слоя донора. Размер 6 767 856 байт, SHA-256 `023276e781975b6e4ca5ab3ac39855f831f6132eb57e6e0b141018e92c2aabed`. Проверены digest сжатого слоя и digest после распаковки. Заголовок конечного ELF содержит `EM_X86_64`. [Слой донора](https://quay.io/v2/cilium/cilium-bpftool/blobs/sha256:0fc776aac493b53bb745dee2bf518f10d3f4da3780642f59f74c86f511c1de85), [сборка amd64](https://github.com/cilium/image-tools/actions/runs/41473855377/job/125374820815).

В таблице смещения указаны в байтах от начала соответствующего файла. Для каждой строки SHA-256 диапазона совпал в объекте статического архива и в исполняемом файле. Диапазон соответствует полному телу функции без релокаций. Повторное чтение четырёх диапазонов дало те же хеши.

| Пакет Ubuntu | Объект | Смещение в объекте | Смещение в bpftool | Длина | SHA-256 диапазона |
| --- | --- | ---: | ---: | ---: | --- |
| glibc `2.39-0ubuntu8.3` | `strcmp-avx2.o` | 96 | 4579696 | 1365 | `efe72148f9518493150860e6a0251517444bcbe2dbecb6ed0f629aea8c8f1852` |
| elfutils `0.190-1.1build4` | `gelf_xlate.o` | 3104 | 503184 | 580 | `904c0d421a2639b726d09357f0404f168599a786c80101c6d62547a45b4830ed` |
| zlib `1:1.3.dfsg-3.1ubuntu2.1` | `adler32.o` | 64 | 3702448 | 1716 | `1d238b00ed5d06f8dff6c5817b1e96cd3a2f32c78b824467198c383098f5abce` |
| libzstd `1.5.5+dfsg2-2build1.1` | `zstd_fast.o` | 3872 | 3817168 | 15001 | `88b9b0dff710b4f9564c954c71f92121dae2140e6677e99feb8e77fb75806eb5` |

При воспроизведении сверьте SHA-256 каждого пакета с индексом Ubuntu и извлеките статический архив. Архив совпал с файлом сборочного образа побайтно. В каждом объекте проверены класс ELF64, код архитектуры 62 и смещение совпавшей функции.

| Пакет amd64 | SHA-256 файла .deb | Архив | SHA-256 архива |
| --- | --- | --- | --- |
| [libc6-dev](https://snapshot.ubuntu.com/ubuntu/20241119T165000Z/pool/main/g/glibc/libc6-dev_2.39-0ubuntu8.3_amd64.deb) | `2fa5027a8251b3aab324ecc5ff9d85215d109ea157d9eb765700b75c4d99c8fc` | `/usr/lib/x86_64-linux-gnu/libc.a` | `6b62accf9b523ffe954cbe797b63d05d31a7d9f1114be1c9db33e020a22ad93f` |
| [libelf-dev](https://snapshot.ubuntu.com/ubuntu/20241119T165000Z/pool/main/e/elfutils/libelf-dev_0.190-1.1build4_amd64.deb) | `540ef7d433b642c9333374e9580dd3cc21b1ef9532787d994998b5131ef82ea4` | `/usr/lib/x86_64-linux-gnu/libelf.a` | `830e67ec963f31e015f76863394d8313e3b7d5232bab1ce6e5efdf3f684e6019` |
| [zlib1g-dev](https://snapshot.ubuntu.com/ubuntu/20241119T165000Z/pool/main/z/zlib/zlib1g-dev_1.3.dfsg-3.1ubuntu2.1_amd64.deb) | `023cbe9dbf0af87f10e54e342c67571874e412b9950d89c6cd7b010be2e67c3c` | `/usr/lib/x86_64-linux-gnu/libz.a` | `436f7e661f703c8959b1e7a77b0450fd9b89ccafce9736804665c27f1bfb27b2` |
| [libzstd-dev](https://snapshot.ubuntu.com/ubuntu/20241119T165000Z/pool/main/libz/libzstd/libzstd-dev_1.5.5+dfsg2-2build1.1_amd64.deb) | `6c9d2b5677a4677e9ead62f74723bb919113621a8028ed543a4d78952d54d165` | `/usr/lib/x86_64-linux-gnu/libzstd.a` | `3b002d21b06091605db4a98c3739b479bd1126bac91b389a9e4a9e75612848ab` |

В сборочном образе присутствуют пакеты нескольких архитектур. При первоначальной выборке только по имени поля архитектуры расходились с архитектурой ELF. Для всех четырёх пакетов выбрана единственная установленная запись dpkg по имени и `amd64`. Архитектура и версия сверены с подписанным индексом и полем Control в соответствующем пакете.

Архивный ключ Ubuntu 2018 с отпечатком `F6ECB3762474EDA9D21B7022871920D1991BC93C` подтвердил подписи обоих InRelease. Пакеты сверены с точными путями, размерами и SHA-256 из проверенных индексов amd64. [Отпечаток Ubuntu](https://documentation.ubuntu.com/security/software-integrity/image-verification/), [noble](https://snapshot.ubuntu.com/ubuntu/20241119T165000Z/dists/noble/InRelease), [noble-updates](https://snapshot.ubuntu.com/ubuntu/20241119T165000Z/dists/noble-updates/InRelease).

Эти совпадения подтверждают присутствие конкретного кода четырёх библиотек в данном бинарном файле. Полное покрытие образа требует описи остальных нативных компонентов.

## Результат сканирования в одноразовом кластере

На коммите `f5c5bafd5bebc649036976049c0bf71883d95c85` аудит сопоставил четыре пакета с бюллетенями Ubuntu на той же базе Grype, что и остальные образы. SHA-256 базы `08b302c006875468fc087630ba33be9d814a2585047ddc874c8cd7a8bfab0d1b`. Проверка версии glibc обнаружила CVE-2025-0395 у пакета 2.39-0ubuntu8.3. На контрольных метаданных версии 2.39-0ubuntu8.4 совпадение исчезло. [Полный аудит и очистка кластера](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/45041076819/attempts/1), [бюллетень Ubuntu](https://ubuntu.com/security/notices/USN-7259-1).

| Пакет | Совпадений | Распределение |
| --- | ---: | --- |
| libc6-dev | 31 | 30 Medium, 1 Negligible |
| libelf-dev | 7 | 4 Medium, 3 Low |
| zlib1g-dev | 2 | 1 Medium, 1 Low |
| libzstd-dev | 0 | База не вернула совпадений |

Все 215 ранее учтённых совпадений Cilium сохранены. К ним добавились 40 совпадений по версиям четырёх пакетов. Десять идентификаторов впервые появились в общей описи платформы. Всего в запуске 399 уникальных идентификаторов, покрыты 12 из 14 образов. Для Cilium сохраняется частичное покрытие. Проверка версий библиотек подтверждает совпадения с бюллетенями на уровне пакета. Для определения достижимости затронутых функций потребуются отдельные доказательства. Выпуск заблокирован.
