# EyeDB Storage Manager

Copyright (c) SYSRA, 1995-1999,2004-2008, 2018

## Licensing

EyeDB Storage Manager is distributed under the GNU Lesser General Public License. Refer to file COPYING.LESSER for full text of the license.

## Compiling EyeDB Storage Manager

### Prerequisites

In order to compile EyeDB Storage Manager, you need the following tools: 

* GNU make
* C++ compiler

If compiling from a `git clone`, you will also need:

* autoconf
* libtool

Please refer to your distribution to check if these tools are packaged for your distribution (which is very likely the case) and to get their respective installation instructions.

#### Prerequisites installation for Debian/Ubuntu

```
apt-get install autoconf libtool make g++ pkg-config
```

#### Prerequisites installation for CentOS/Fedora

```
yum -y install git autoconf libtool make gcc-c++ pkgconfig
```

### Compiling

If compiling from a `git clone` and not from a tarball, first run:

```
./autogen.sh
make
```

Then, run `configure` script:

```
./configure
```

`configure` script takes the following useful options:

```
--prefix=PREFIX
            to specify installation root directory 
            (default is /usr)
--enable-debug
            to compile with debug (default is no)
--enable-optimize=FLAG
            to compile with given optimization flag, for 
            instance --enable-optimize=-O2
            (default is no optimization)
```

Full description of `configure` options can be obtained with:

```
./configure --help
```

Once `configure` script executed, compilation can be launched by:

```
make
```

### Installing
----------------

After compiling, you can install it with the usual:

```
make install
```

This will install EyeDB Storage Manager in the directories that you have given when running the configure script.

