# Клонирование репозитория GOST engine
git clone https://github.com/gost-engine/engine
cd engine
git submodule update --init
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
sudo make install
# Проверка расположения директорий движков OpenSSL
openssl version -e
# Конфигурация OpenSSL
openssl_conf = openssl_def
[openssl_init]
engines = engine_section
[engine_section]
gost = gost_section
[gost_section]
engine_id = gost
default_algorithms = ALL
CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet
default_algorithms = ALL
# Проверь что ГОСТ работает
openssl engine gost -c
openssl req -newkey gost2001 -pkeyopt paramset:A -out /tmp/gost.csr -keyout /tmp/gost.key
# Если нет добейся чтобы работал
# Установи зависимостей
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config bison flex libpopt-dev \
  libselinux1-dev libsqlite3-dev libarchive-dev libcap-dev libacl1-dev \
  libaudit-dev libbz2-dev liblzma-dev libzstd-dev libssl-dev \
  libmagic-dev zlib1g-dev python3-dev liblua5.4-dev debugedit \
  rsync git gpg automake autoconf gettext libtool pkgconf \
  autopoint python3-all python3-all-dev texinfo transfig fig2dev imagemagick \
  file ghostscript swig doxygen graphviz libz-dev libldap2-dev \
  libgnutls28-dev libcurl4-gnutls-dev libreadline-dev librsvg2-bin \
  libusb-1.0-0-dev libgpg-error-dev libassuan-dev libgcrypt20-dev \
  libksba-dev libnpth0-dev autoconf automake libtool gettext bison texinfo \
  gcc make libgpg-error-dev libgcrypt20-dev
  
# Клонировать репозиторий libksba с поддержкой ГОСТ
git clone https://github.com/nicesoft-labs/libksba.git
cd libksba
git checkout master

# Сборка и установка
./autogen.sh --force
./configure --enable-maintainer-mode
make -j$(nproc)
sudo make install

# Клонировать репозиторий GnuPG с поддержкой ГОСТ
git clone https://github.com/nicesoft-labs/gnupg.git
cd gnupg
git checkout feature/gost-support

# Сборка и установка
./autogen.sh --force
./configure --enable-maintainer-mode
make -j$(nproc)
sudo make install

# Сборка RPM
mkdir build2 && cd build2
cmake .. \
  -DENABLE_BDB_RO=ON \
  -DENABLE_SQLITE=ON \
  -DRPM_VENDOR="niceos" \
  -DWITH_OPENSSL=ON \
  -DWITH_SELINUX=ON \
  -DENABLE_PYTHON=ON \
  -DENABLE_PLUGINS=ON \
  -DWITH_CAP=ON \
  -DWITH_ACL=ON \
  -DWITH_INTERNAL_OPENPGP=ON \
  -DWITH_ARCHIVE=ON \
  -DWITH_AUDIT=ON \
  -DENABLE_NDB=OFF \
  -DENABLE_OPENMP=OFF \
  -DWITH_IMAEVM=ON \
  -DENABLE_NLS=ON \
  -DWITH_FAPOLICYD=ON \
  -DENABLE_TESTSUITE=OFF
make -j$(nproc)

# затем запиши в файл /root/stan01-key.asc этот ключ:

-----BEGIN PGP PUBLIC KEY BLOCK-----

mFEEaGPbbBMHKoUDAgIjAQIDBNB9TKnmWBvFzIEoSw3XGSznQbEhd0DZOEXyTkr6
kRCBARvO4MhBpveoj46e+SLYquv9LIOlTQa+PAPV3ls0t3y0FnN0YW4wMSA8c3Rh
bjAxQHN0YW4wMT6IkwQTE6YAOxYhBKGIhyg81aOTOo4HXW2o0V0LJee/BQJoY9ts
AhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEG2o0V0LJee/90cBAPQv
lvG8eGt0JuOY4JCzNS6TSZyub74BItnN7VReMDr1AP4j1w/0B+unbORjjS+zWnB9
Ub/XleYEd8Z4CiULze2tuLhfBGhj22wSByqFAwICIwECAwTWKSZS2aeISR4D8MV0
qwwZklJnec8u9eiytXjgd5z7hnE42QIlEvy6cTAwEpldFLZi2WWkgMmDyIR7EQoI
5SbZDQIBCKYBAaoBAHIBqgGIeAQYE6YAIBYhBKGIhyg81aOTOo4HXW2o0V0LJee/
BQJoY9tsAhsMAAoJEG2o0V0LJee/scoA/1Yw18xxA3LOD4N3BnxqgXVCwdpCJPmn
9bX3VfgjVVaLAQCW/kut8aA3ubFN4/rhsTK/qdQttHq0cGMxIM5mPPGo+Q==
=M+Qx
-----END PGP PUBLIC KEY BLOCK-----

# и попытайся его импортировать. 
rpm -vvvvv --import /root/stan01-key.asc
