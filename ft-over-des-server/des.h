#ifndef DES_H
#define DES_H

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

typedef unsigned bit_num_t;

// 以下一组类型定义和常量规定了一种块，配套使用
// 所有类型均右对齐
typedef uint64_t block_t;
constexpr bit_num_t BLOCK_NUM = 64;

typedef uint32_t half_block_t;
constexpr bit_num_t HALF_BLOCK_NUM = BLOCK_NUM / 2;

typedef uint64_t K_t;
constexpr bit_num_t K_NUM = 48;

typedef uint32_t CD_t;
constexpr bit_num_t CD_NUM = 28;

typedef uint64_t double_CD_t;
constexpr bit_num_t DOUBLE_CD_NUM = CD_NUM * 2;

/// 加密方向
enum direction_t
{
    /// 解密
    DECIPHER = -1,
    /// 加密
    ENCIPHER = 1
};


constexpr int ITERATION_NUM = 16;

// 以下是算法中各个常量数组，用作位映射
constexpr bit_num_t P_map[HALF_BLOCK_NUM] =
{
    16, 7,20,21,
    29,12,28,17,
     1,15,23,26,
     5,18,31,10,
     2, 8,24,14,
    32,27, 3, 9,
    19,13,30, 6,
    22,11, 4,25
};

constexpr bit_num_t E_map[K_NUM] =
{
    32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32, 1
};

constexpr bit_num_t IP_map[BLOCK_NUM] =
{
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
};

constexpr bit_num_t invIP_map[BLOCK_NUM] =
{
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41, 9,49,17,57,25
};

/// S1-S8，定义在一个数组里
constexpr bit_num_t S[8][4][16] =
{
    // S1
    14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
     0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
     4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
    15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13,
    // S2
    15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
     3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
     0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
    13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9,
    // S3
    10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
    13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
    01,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12,
    // S4
     7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
    13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
    10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
    03,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14,
    // S5
     2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
    14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
     4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
    11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3,
    // S6
    12,1 ,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
    10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
     9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
    04, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13,
    // S7
     4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
    13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
     1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
    06,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12,
    // S8
    13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
     1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
     7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
     2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11
};

class Des
{
private:
    /// 算法中的右边补位的左移.
    /// @param[in]	CD	输入数据块
    /// @param[in]	n	左移位数
    /// @return			左移结果
    static CD_t left_shift(CD_t const& CD, bit_num_t const n)
    {
        return
            /** 左移的部分需要进行高位清0，以免影响后续操作. */
            ((CD << n) & ((CD_t(1) << CD_NUM) - 1))
            |
            (CD >> (CD_NUM - n));
    }

public:
    /// 类似算法中的KS，但是一次性生成所有K密钥组，进行文件加密前即调用完毕.
    /// @param[in]	KEY	原密钥
    /// @param[out]	K	生成结果存储向该指针指向的数组	
    static void KS(block_t const KEY, K_t* const K)
    {
        /// PC-1数组，分两部分
        constexpr bit_num_t PC_1_map[2][CD_NUM] =
        {
            57,49,41,33,25,17, 9,
             1,58,50,42,34,26,18,
            10, 2,59,51,43,35,27,
            19,11, 3,60,52,44,36,

            63,55,47,39,31,23,15,
             7,62,54,46,38,30,22,
            14, 6,61,53,45,37,29,
            21,13, 5,28,20,12, 4
        };
        /// PC-2数组
        constexpr bit_num_t PC_2_map[K_NUM] =
        {
            14,17,11,24, 1, 5,
             3,28,15, 6,21,10,
            23,19,12, 4,26, 8,
            16, 7,27,20,13, 2,
            41,52,31,37,47,55,
            30,40,51,45,33,48,
            44,49,39,56,34,53,
            46,42,50,36,29,32
        };

        auto C = bit_map<block_t, CD_t>(KEY, BLOCK_NUM, PC_1_map[0], CD_NUM);
        auto D = bit_map<block_t, CD_t>(KEY, BLOCK_NUM, PC_1_map[1], CD_NUM);

        for (unsigned n = 1; n != ITERATION_NUM + 1; ++n)
        {
            switch (n)
            {
            case 1:
            case 2:
            case 9:
            case 16:
                C = left_shift(C, 1);
                D = left_shift(D, 1);
                break;
            default:
                C = left_shift(C, 2);
                D = left_shift(D, 2);
                break;
            }
            K[n - 1] = bit_map<double_CD_t, K_t>((double_CD_t(C) << CD_NUM) | D, DOUBLE_CD_NUM, PC_2_map, K_NUM);
        }
    }

private:
    /// 数据块按位映射.
    /// @param[in]	input_block	输入数据块，位数应该大于等于size_in
    /// @param[in]	size_in		输入数据块的大小
    /// @param[in]	iter		指向替换规则数组的指针，根据数组将某位（从0开始）替换为该位所对应下标的对应值（从1开始的序数）所指示的位
    /// @param[in]	size_out	permutation_ptr所指数组的长度
    /// @return					替换后的数据块，位数应该大于等于size_out
    template<typename T_in, typename T_out>
    static T_out bit_map(T_in const input_block, bit_num_t const size_in, bit_num_t const* iter, bit_num_t const size_out)
    {
        auto end = iter + size_out;

        T_out output_block = (input_block >> (size_in - *iter)) & 1;
        ++iter;
        for (; iter != end; ++iter)
        {
            // 右对齐置位，并避免分支
            output_block <<= 1;
            output_block |= (input_block >> (size_in - *iter)) & 1;
        }
        return output_block;
    }

    /// 同算法中的IP.
    static block_t IP(block_t const input_block)
    {
        return bit_map<block_t, block_t>(input_block, BLOCK_NUM, IP_map, BLOCK_NUM);
    }

    /// 同算法中的IP-1
    static block_t invIP(block_t const preoutput_block)
    {
        return bit_map<block_t, block_t>(preoutput_block, BLOCK_NUM, invIP_map, BLOCK_NUM);
    }

    /// 同算法中的E
    static K_t E(half_block_t const R)
    {
        return bit_map<half_block_t, K_t>(R, HALF_BLOCK_NUM, E_map, K_NUM);
    }

    /// 算法中S1-S8的总和.
    /// @param[in]	B_group	B1-B8的总和，右对齐
    /// @return				S替换后的总和，右对齐
    static half_block_t S_group(K_t B_group)
    {
        half_block_t L = 0;
        for (int n = 7; n != -1; --n)
        {
            unsigned i = 0, j = 0;
            // B的第1位与i的第1位对齐
            i = B_group & 1;
            // B的第2-5位与j的1-4位对齐
            B_group >>= 1;
            j = B_group & 0xf;
            // B的第6位与i的第2位对齐
            B_group >>= 3;
            i |= B_group & 2;

            L |= S[n][i][j] << (7 - n) * 4;

            // 进入下一个B
            B_group >>= 2;
        }
        return L;
    }

    /// 同算法中的P
    static half_block_t P(half_block_t const L)
    {
        return bit_map<half_block_t, half_block_t>(L, HALF_BLOCK_NUM, P_map, HALF_BLOCK_NUM);
    }

    /// 同算法中的f
    static half_block_t f(half_block_t const R, K_t const K)
    {
        return P(S_group(K ^ E(R)));
    }

public:
    /// 对一个数据块的加密解密算法.
    /// @param[in]	input_block	输入数据块
    /// @param[in]	K			密钥组
    /// @param[in]	direction	加密方向，加密（值：ENCIPHER）或解密（值：DECIPHER）
    /// @return					加密后的数据块
    static block_t cipher_block(block_t const input_block, K_t const* const K, direction_t const direction)
    {
        auto const permuted_input_block = IP(input_block);
        half_block_t L = permuted_input_block >> HALF_BLOCK_NUM;
        half_block_t R = half_block_t(permuted_input_block);
        // 用direction计算迭代中调用密钥组的顺序，ENCIPHER则正向调用密钥组，DECIPHER则反向调用密钥组
        int end = ((ITERATION_NUM - 1) + (ITERATION_NUM + 1) * direction) / 2;
        for (int n = ((ITERATION_NUM - 1) * (1 - direction)) / 2; n != end; n += direction)
        {
            auto L_then = L;
            L = R;
            R = L_then ^ f(R, K[n]);
        }
        return invIP((block_t(R) << HALF_BLOCK_NUM) | L);
    }
};

#endif // DES_H
