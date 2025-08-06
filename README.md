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
```

## ⚙ Configuration (nginx.conf)
```nginx
http {
    gpg_log_recipient securelog@example.com;
    gpg_log_path /usr/local/nginx/temp/securelog;
    gpg_log_rotation hourly;  # Options: hourly, daily, weekly, monthly

    server {
        listen 80;
        server_name localhost;

        location / {
            root /usr/share/nginx/html;
        }
    }
}
```

## 📁 Log Filename Format
| Rotation | Filename Example               |
|:---------|:-------------------------------|
| Hourly   | `nginx-20250806-1300.log.gpg` |
| Daily    | `nginx-20250806-0000.log.gpg` |
| Weekly   | `nginx-2025W32-0000.log.gpg`  |
| Monthly  | `nginx-202508-0000.log.gpg`   |


## 🔒 Security Notes
- Logs are encrypted using the configured GPG recipient
- Only the recipient with the private key can decrypt the logs
- GPG must be installed and configured on the system

## 📄 License
This module is released under the MIT License. See the LICENSE file for details.

## 🤝 Contributions
Pull requests and issues are welcome. Please ensure your code is clean and well-documented.
