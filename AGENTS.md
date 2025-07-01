First, clone the `gost-support` branch from our repository:
git clone --branch feature/gost-support https://github.com/nicesoft-labs/gnupg.git

then install 

sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config bison flex libpopt-dev \
    libselinux1-dev libsqlite3-dev libarchive-dev libcap-dev libacl1-dev \
    libaudit-dev libbz2-dev liblzma-dev libzstd-dev libssl-dev \
    libmagic-dev zlib1g-dev python3-dev liblua5.4-dev debugedit \
    rsync build-essential git gpg automake autoconf gettext libtool pkgconf \
  autopoint python3-all python3-all-dev texinfo transfig fig2dev imagemagick \
  file ghostscript swig doxygen graphviz libz-dev libbz2-dev libldap2-dev \
  libsqlite3-dev libgnutls28-dev libcurl4-gnutls-dev libreadline-dev librsvg2-bin \
  libusb-1.0-0-dev libgpg-error-dev libassuan-dev libgcrypt20-dev libksba-dev \
  libnpth0-dev

  then 
  cd gnupg
  ./autogen.sh --force
  ./configure --enable-maintainer-mode --prefix=/usr/local --enable-large-secmem --disable-doc
make -j$(nproc)
sudo make install
then clone rpm repository and build rpm
then
mkdir build2 && cd build2
cmake .. \
  -DENABLE_BDB_RO=ON \
  -DENABLE_SQLITE=ON \
  -DRPM_VENDOR="niceos" \
  -DWITH_OPENSSL=ON \
  -DWITH_SELINUX=ON \
  -DENABLE_PYTHON=ON \
  -DWITH_INTERNAL_OPENPGP=OFF \
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

echo "📁 Создаю каталоги для rpmbuild..."
mkdir -p ~/rpmbuild/{SPECS,SOURCES,BUILD,RPMS,SRPMS}

echo "✏️ Записываю ~/.rpmmacros..."
echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros

echo "📝 Пишу hello.spec..."
cat > ~/rpmbuild/SPECS/hello.spec <<EOF
Name:           hello
Version:        1.0
Release:        1%{?dist}
Summary:        Simple hello world package

License:        MIT
URL:            https://example.com
Source0:        hello.sh

BuildArch:      noarch

%description
A simple package that prints Hello World.

%prep

%build

%install
mkdir -p %{buildroot}/usr/bin
install -m 0755 %{SOURCE0} %{buildroot}/usr/bin/hello

%files
/usr/bin/hello

%changelog
* Tue Jul 01 2025 You <you@example.com> - 1.0-1
- Initial package
EOF

echo "📜 Создаю hello.sh..."
cat > ~/rpmbuild/SOURCES/hello.sh <<EOF
#!/bin/bash
echo "Hello, world!"
EOF

chmod +x ~/rpmbuild/SOURCES/hello.sh

echo "⚙️ Стартую rpmbuild..."
rpmbuild -ba ~/rpmbuild/SPECS/hello.spec

echo "✅ Готово!"
echo "Проверяй: ~/rpmbuild/RPMS/noarch/"
