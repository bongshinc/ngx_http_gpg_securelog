# ngx_http_gpg_securelog_module

A dynamic NGINX module for secure logging using GPG encryption.  
This module encrypts HTTP request logs with GPG and stores them in date-based secure log files.

## 🔐 Features

- Real-time GPG encryption of access logs
- Daily log file rotation with append mode
- Configurable recipient and log path
- Easy integration with NGINX 1.28.0+
- Compatible with dynamic module loading

## ⚙️ Installation

```bash
git clone https://github.com/bongshinc/ngx_http_gpg_securelog_module.git
cd nginx-1.28.0
./configure --add-dynamic-module=../ngx_http_gpg_securelog_module
make modules

