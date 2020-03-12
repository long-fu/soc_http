#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
// gethostname
#include <unistd.h>

#include <netdb.h>
static int af = 0;

int main(int argc, char const *argv[])
{
    int sock,n;
    struct hostent *hent;
    
    struct sockaddr_in servaddr = { 0 };

    char host_name[] = "www.csdn.net";
    char ip[32] = { 0 };
    
    char buf[] = "GET /index.html HTTP/1.1\r\n\
Host: 47.95.164.112:8080\r\n\
Proxy-Connection: keep-alive\r\n\
Cache-Control: max-age=0\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36\r\n\
Accept-Encoding: gzip,deflate,sdch\r\n\
Accept-Language: zh-CN,zh;q=0.8,en;q=0.6\r\n\
\r\n";
    
    char rbuf[2048] = { 0 };
    
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        perror("tcp creat error");
        exit(sock);
    }
    

    if (gethostname(host_name, sizeof(host_name)) < 0) {
        perror("gethostname");
    }


    printf("%s -- %d",host_name,sizeof(host_name));
    if((hent = gethostbyname(host_name))==NULL){
        perror("ip error");
        exit(2);
    }

    {
           int32_t ipi = 0;
           ipi = (*(*hent->h_addr_list + 3) << 24) & 0xFF000000;
           ipi |= ((*(*hent->h_addr_list + 2) << 16)  & 0xFF0000);
           ipi |= ((*(*hent->h_addr_list + 1) << 8) & 0xFF00);
           ipi |= ((*(*hent->h_addr_list + 0) << 0) & 0xFF);
           printf("地址 0x%x \n",ipi);//这也是正确的ip地址流 对位操作的时候需要知道 大小端 熟悉指针操作
    }
    //获取到网络类型 ipv4 ipv6 两个类型 网络地址族
    printf("协议族 %d\n",hent->h_addrtype);
    
    //解析出 点分 地址
    //网络字节流 ——》IP字符串 0.0.0.0
    if (inet_ntop(hent->h_addrtype,(void *)hent->h_addr_list[0],ip,sizeof(ip)) == NULL) {
        perror("inet_ntop error");
        exit(4);
    }
    
    printf("10点分ip %s\n",ip);
    //IP字符串 ——》网络字节流
    if(inet_pton(hent->h_addrtype,ip,&servaddr.sin_addr) <= 0){
        perror("inet_pton error");
        exit(5);
    }
    
    printf("ips 0x%x\n",servaddr.sin_addr);

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(80);
    
    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect error\n");
        exit(6);
    }
    
    write(sock, buf, strlen(buf));
    
    while ((n = read(sock, rbuf, 2048))>0) {
        rbuf[n] = 0;
        printf("%s", rbuf);
    }
    printf("ok\n");
    close(sock);

    return 0;
}
