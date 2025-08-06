# ngx_http_gpg_securelog
NGINX module for encrypted logging using GPG

A custom NGINX module for secure logging using GPG encryption. This module captures HTTP request metadata and writes it to encrypted log files, with support for flexible rotation intervals and timestamped filenames.

## 🔐 Features

- Logs client IP, request method, URI, and User-Agent
- Encrypts logs using GPG public key
- Supports log rotation by hour, day, week, or month
- Automatically generates timestamped log filenames
- Uses default values if configuration is missing

## 🛠 Installation

1. Clone or copy the module source into your NGINX source tree
2. Rebuild NGINX with the module:

```bash
./configure --add-module=/path/to/ngx_http_gpg_securelog
make
sudo make install
