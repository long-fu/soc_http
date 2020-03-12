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


static int on_info(http_parser* p) {
  printf("on_info %d\r\n",p->flags);
  return 0;
}


static int on_headers_complete(http_parser* p) {
  printf("on_headers_complete %d\r\n",p->method);
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

static int on_header_field(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("%s: ",buffer);
    return 0;
}

static int on_header_value(http_parser* p, const char *at, size_t length) {
    char buffer[1024] = {0};
    strncpy(buffer,at,length);
    printf("%s\r\n",buffer);
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
  .on_header_field = on_header_field,
  .on_header_value = on_header_value,
  .on_url = on_url,
  .on_status = on_status,
  .on_body = on_body
};

// int bench(int iter_count, int silent) {
//   struct http_parser parser;


//     fprintf(stderr, "req_len=%d\n", (int) data_len);
//     size_t parsed;
//     http_parser_init(&parser, HTTP_REQUEST);

//     parsed = http_parser_execute(&parser, &settings, data, data_len);
//     if (parsed == data_len) {
//         printf("解析成功 %zu",parsed);
//     } else {
//         printf("解析失败  %zu", parsed);
//     }
    
//     printf("返回");
//   return 0;
// }

struct http_parser parser_response;
int is_init = 0;

int
parser_responder(char *data,size_t data_len)
{
    size_t parsed;
    if (is_init == 0) 
    {
        http_parser_init(&parser_response, HTTP_RESPONSE);
        is_init = 1;
    }
    parsed = http_parser_execute(&parser_response, &settings, data, data_len - 1);
        
    if (parsed == data_len) {
        printf("解析成功 %zu",parsed);
    } else {
        printf("解析失败  %zu", parsed);
    }
    printf("解析一次最后返回");
    return 0;
}

static int sock = 0;

int 
on_recive_request(const char *url,const int port, const char *http_heads) 
{
    int sock,n;
    struct hostent *hent;
    
    struct sockaddr_in servaddr = { 0 };

    char ip_address[32] = { 0 };
    
    char rbuf[2048] = { 0 };
    
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("tcp creat error");
        exit(1);
    }
    
    printf("请求地址 %s\r\n",url);
    if((hent=gethostbyname(url))==NULL){
        perror("ip error");
        exit(2);
    }

    {
        int32_t ipi = 0;
        ipi = (*(*hent->h_addr_list + 3) << 24) & 0xFF000000;
        ipi |= ((*(*hent->h_addr_list + 2) << 16)  & 0xFF0000);
        ipi |= ((*(*hent->h_addr_list + 1) << 8) & 0xFF00);
        ipi |= ((*(*hent->h_addr_list + 0) << 0) & 0xFF);
        printf("ip地址 0x%x \n",ipi);//这也是正确的ip地址流 对位操作的时候需要知道 大小端 熟悉指针操作
    }
    //获取到网络类型 ipv4 ipv6 两个类型 网络地址族
    printf("协议族类型 %d\n",hent->h_addrtype);
    
    //解析出 点分 地址
    //网络字节流 ——》IP字符串 0.0.0.0
    if (inet_ntop(hent->h_addrtype,(void *)hent->h_addr_list[0],ip_address,sizeof(ip_address)) == NULL) {
        perror("inet_ntop error");
        exit(4);
    }
    printf("IP address %s \r\n", ip_address);
    //IP字符串 ——》网络字节流
    if(inet_pton(hent->h_addrtype,ip_address,&servaddr.sin_addr) <= 0){
        perror("inet_pton error");
        exit(5);
    }
    
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    
    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect error\n");
        exit(6);
    }
    
    int result = write(sock, http_heads, strlen(http_heads));
    if (result != strlen(http_heads)) {
        perror("数据写入失败");
        exit(-1);
    }
    
    printf("开始接受数据 %d\r\n",sock);
    int ri = 0;
    while ((n = read(sock, rbuf, 2048))>0) {
        rbuf[n] = 0;
        printf("%d 接受的数据 %s \r\n",ri ,rbuf);
        parser_responder(rbuf,strlen(rbuf));
        ri ++;
    }
    close(sock);
    printf("数据接收完成 %d", n);
    return 0;
} 

int main(int argc, char** argv)
{
    char host_name[] = "www.csdn.net";

    char http_header[] = "GET /index.html HTTP/1.1\r\n\
Host: 47.95.164.112:8080\r\n\
Proxy-Connection: keep-alive\r\n\
Cache-Control: max-age=0\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36\r\n\
Accept-Encoding: gzip,deflate,sdch\r\n\
Accept-Language: zh-CN,zh;q=0.8,en;q=0.6\r\n\
\r\n";
   int port = 80;
   on_recive_request(host_name,port,http_header);

}
