#include <sys/unistd.h>
#include <string.h>
#include <stdio.h>


constexpr auto OUT_NAME = "ft-over-des-client";
extern "C"
{
	int connectTCP(const char* host, const char* service);
}
#include "../des.h"

inline void do_client(char const* host, char const* service, char const* source_path, char const* dest_path)
{
	// 0. 创建一个TCP连接
	auto fd = connectTCP(host, service);


	auto len = strlen(source_path);
	// 2. send源文件路径长度
	write(fd, &len, sizeof(len));
	// 4. send源文件路径
	write(fd, source_path, len * sizeof(source_path[0]));

	long f_size;
	// 7. recv文件大小
	read(fd, &f_size, sizeof(f_size));
	// 整块缓冲区大小，文件大小向上取整
	auto buf_size = (f_size - 1) / sizeof(block_t) + 1;
	// 分配整块缓冲区
	auto buf = new block_t[buf_size];

	// 9. recv加密的整块数据
	read(fd, buf, buf_size * sizeof(buf[0]));
	// delete
	close(fd);
	auto end = buf + buf_size;

	// 需要解密时输入KEY并且生成K密钥组，解密完即释放KEY和K
	printf("un-prefixed uppercase hexadecimal KEY: ");
	{
		block_t KEY;
		scanf("%llX", &KEY);
		K_t K[ITERATION_NUM];
		// 生成密钥组
		Des::KS(KEY, K);

		// 逐块解密所有块
		for (auto iter = buf; iter != end; ++iter)
		{
			*iter = Des::cipher_block(*iter, K, DECIPHER);
		}
	}

	// 打开目的文件
	auto dest = fopen(dest_path, "wb");
	if (!dest)
	{
		printf("%s: cannot stat \'%s\': No such file\n", OUT_NAME, dest_path);
		delete[] buf;
		exit(EXIT_FAILURE);
	}

	// 把源文件大小的解密后数据写入目的文件
	fwrite(buf, f_size, 1, dest);
	puts("Succeed!");

	// delete
	fclose(dest);
	// delete
	delete[] buf;
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
			printf("Usage: %s [OPTION] HOST PORT SOURCE DEST\n", OUT_NAME);
			puts("Get encrypted file from web HOST and PORT and SOURCE path, decrypt it and write it to local DEST path.");
			putchar('\n');
			puts("      --help     display this help and exit");
		}
		else
		{
			printf("%s: unrecognized option \'%s\'\n", OUT_NAME, argv[1]);
			put_help();
		}
		break;
	}
	case 5:
	{
		do_client(argv[1], argv[2], argv[3], argv[4]);
		break;
	}
	default:
		puts("Argument numbers error");
		put_help();
		break;
	}
	return 0;
}
