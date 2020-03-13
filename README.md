## 运行

```sh
gcc -c main.c http_parser.c
gcc -o main main.o http_parser.o /usr/local/opt/openssl@1.1/lib/libssl.a /usr/local/opt/openssl@1.1/lib/libcrypto.a
./main
```