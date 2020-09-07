#include <sys/unistd.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

extern "C"
{
    int passiveTCP(const char* service, int qlen);
}

#include "../des.h"

constexpr int QLEN = 8;
constexpr auto OUT_NAME = "ft-over-des-server";



inline void do_server(char const* service)
{
    // 创建一个TCP socket
    auto pre_accept_fd = passiveTCP(service, QLEN);

    // 输入密钥KEY，生成完K即释放KEY
    printf("un-prefixed uppercase hexadecimal KEY: ");
    K_t K[ITERATION_NUM];
    {
        block_t KEY;
        scanf("%llX", &KEY);
        // 生成密钥组
        Des::KS(KEY, K);
    }


    while (1)
    {
        sockaddr sad;
        socklen_t slen;
        // 1. socket开始accept
        auto fd = accept(pre_accept_fd, &sad, &slen);
        size_t len;
        // 3. recv源文件路径长度
        read(fd, &len, sizeof(len));

        auto source_path = new char[len];
        // 5. recv源文件路径
        read(fd, source_path, len * sizeof(source_path[0]));
        // 打印客户端请求的文件路径
        printf("Requested: %s: ", source_path);

        // 打开源文件
        auto source = fopen(source_path, "rb");
        if (!source)
        {
            printf("\n%s: cannot stat \'%s\': No such file\n", OUT_NAME, source_path);
            delete[] source_path;
            close(fd);
            continue;
        }
        // delete
        delete[] source_path;

        // 获取文件大小
        fseek(source, 0, SEEK_END);
        auto f_size = ftell(source);
        // 6. send文件大小
        write(fd, &f_size, sizeof(f_size));
        rewind(source);

        // 整块缓冲区大小，文件大小向上取整
        auto buf_size = (f_size - 1) / sizeof(block_t) + 1;
        // 分配整块缓冲区
        auto buf = new block_t[buf_size];
        // 文件读入整块缓冲区
        fread(buf, buf_size, sizeof(buf[0]), source);
        // delete
        fclose(source);
        auto end = buf + buf_size;

        // 逐块加密所有块
        for (auto iter = buf; iter != end; ++iter)
        {
            *iter = Des::cipher_block(*iter, K, ENCIPHER);
        }
        // 8. send加密的整块数据
        write(fd, buf, buf_size * sizeof(buf[0]));
        puts("Sent successfully!");

        // delete
        delete[] buf;
        // delete
        close(fd);
    }
    // 基本不会执行到这里，以防万一
    close(pre_accept_fd);
}

/// 输出查看帮助
inline void put_help(void)
{
    printf("Try \'%s --help\' for more information.\n", OUT_NAME);
}


int main(int argc, char* argv[])
{
    switch (argc)
    {
    case 2:
    {
        if (!strcmp("--help", argv[1]))
        {
            printf("Usage: %s [OPTION] PORT\n", OUT_NAME);
            puts("Responds to a request for a file, send encrypted file.");
            putchar('\n');
            puts("      --help     display this help and exit");
        }
        else
        {
            do_server(argv[1]);
        }
        break;
    }
    default:
        puts("Argument numbers error");
        put_help();
        break;
    }
    return 0;
}
