# Instructions for building RPM

Этот репозиторий содержит исходный код менеджера пакетов RPM. Для сборки RPM из исходников на системе Ubuntu/Debian выполните следующие действия.

## Установка зависимостей

Необходимо установить следующие пакеты:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config bison flex libpopt-dev \
    libselinux1-dev libsqlite3-dev libarchive-dev libcap-dev libacl1-dev \
    libaudit-dev libbz2-dev liblzma-dev libzstd-dev libssl-dev \
    libmagic-dev zlib1g-dev python3-dev liblua5.4-dev debugedit
```

## Сборка

Создайте отдельную директорию для сборки, выполните `cmake` с требуемыми флагами и соберите проект:

```bash
mkdir build && cd build
cmake .. \
  -DENABLE_BDB_RO=ON \
  -DENABLE_SQLITE=ON \
  -DRPM_VENDOR="niceos" \
  -DWITH_OPENSSL=ON \
  -DWITH_SELINUX=ON \
  -DENABLE_PYTHON=ON \
  -DWITH_INTERNAL_OPENPGP=ON \
  -DENABLE_PLUGINS=ON \
  -DWITH_CAP=ON \
  -DWITH_ACL=ON \
  -DWITH_ARCHIVE=ON \
  -DWITH_AUDIT=ON \
  -DENABLE_NDB=OFF \
  -DENABLE_OPENMP=OFF \
  -DWITH_IMAEVM=ON \
  -DENABLE_NLS=ON \
  -DWITH_FAPOLICYD=ON \
  -DWITH_ZSTD=ON \
  -DENABLE_TESTSUITE=OFF
make -j$(nproc)
```

После успешной компиляции можно установить собранные бинарники:

```bash
sudo make install
