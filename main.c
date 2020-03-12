#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "http_parser.h"

#include <netdb.h>


#include "http_parser.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

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
  printf("on_info %d\r\n",p->flags);
  return 0;
}


static int on_headers_complete(http_parser* p) {
  printf("on_headers_complete %d\r\n",p->type);
  return 0;
}

static int on_message_complete(http_parser* p) {
  printf("on_message_complete %s\r\n",(char*)p->data);
  return 0;
}

static int on_data(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("on_data type: %d %s==%zu\r\n",p->type,buffer,length);
    return 0;
}


static int on_url(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("on_url %s\r\n",buffer);
    return 0;
}

static int on_status(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("on_status %s\r\n",buffer);
    return 0;
}

static int on_body(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("on_body %s\r\n",buffer);
    return 0;
}

static http_parser_settings settings = {
  .on_message_begin = on_info,
  .on_headers_complete = on_headers_complete,
  .on_message_complete = on_message_complete,
  .on_header_field = on_data,
  .on_header_value = on_data,
  .on_url = on_url,
  .on_status = on_status,
  .on_body = on_body
};

int bench(int iter_count, int silent) {
  struct http_parser parser;
  int i;
  int err;
  struct timeval start;
  struct timeval end;

  if (!silent) {
    err = gettimeofday(&start, NULL);
    assert(err == 0);
  }

  fprintf(stderr, "req_len=%d\n", (int) data_len);
    size_t parsed;
    http_parser_init(&parser, HTTP_REQUEST);

    parsed = http_parser_execute(&parser, &settings, data, data_len);

    printf("解析结果  %zu", parsed);
//   if (!silent) {
//     double elapsed;
//     double bw;
//     double total;

//     err = gettimeofday(&end, NULL);
//     assert(err == 0);

//     fprintf(stdout, "Benchmark result:\n");

//     elapsed = (double) (end.tv_sec - start.tv_sec) +
//               (end.tv_usec - start.tv_usec) * 1e-6f;

//     total = (double) iter_count * data_len;
//     bw = (double) total / elapsed;

//     fprintf(stdout, "%.2f mb | %.2f mb/s | %.2f req/sec | %.2f s\n",
//         (double) total / (1024 * 1024),
//         bw / (1024 * 1024),
//         (double) iter_count / elapsed,
//         elapsed);

//     fflush(stdout);
//   }

  return 0;
}

int main(int argc, char** argv) {
  int64_t iterations;

  iterations = kBytes / (int64_t) data_len;
  bench(1, 1);
//   if (argc == 2 && strcmp(argv[1], "infinite") == 0) {
//     for (;;)
//       bench(iterations, 1);
//     return 0;
//   } else {
//     return bench(iterations, 0);
//   }
}
