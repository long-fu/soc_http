
/* 8 gb */
static const int64_t kBytes = 8LL << 30;

static const char data[] =
    "POST /joyent/http-parser HTTP/1.1\r\n"
    "Host: github.com\r\n"
    "DNT: 1\r\n"
    "Accept-Encoding: gzip, deflate, sdch\r\n"
    "Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/39.0.2171.65 Safari/537.36\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/webp,*/*;q=0.8\r\n"
    "Referer: https://github.com/joyent/http-parser\r\n"
    "Connection: keep-alive\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Cache-Control: max-age=0\r\n\r\nb\r\nhello world\r\n0\r\n";
static const size_t data_len = sizeof(data) - 1;

static int on_info(http_parser* p) {
  return 0;
}


static int on_data(http_parser* p, const char *at, size_t length) {
  return 0;
}

static http_parser_settings settings = {
  .on_message_begin = on_info,
  .on_headers_complete = on_info,
  .on_message_complete = on_info,
  .on_header_field = on_data,
  .on_header_value = on_data,
  .on_url = on_data,
  .on_status = on_data,
  .on_body = on_data
};
