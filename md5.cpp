#include <stdio.h>  
#include <string.h>
#include <string>
#include <stdlib.h>  
using namespace std; 

//! 定义MD5状态数据结构类型  
typedef struct  
{  
    unsigned   int      state[4];       // 初始链接变量;保存16字节摘要  
    unsigned   int      count[2];       // 明文位数(用64位保存，count[0]表示低32位，count[1]表示高32位)  
    unsigned char       PADDING[64];    // 填充位，最大64*8位  
    unsigned char       buffer[64];     // 输入缓冲（暂存512位明文）  
}MD5_State;  


//! F, G, H and I 基本MD5函数  
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))  
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))  
#define H(x, y, z) ((x) ^ (y) ^ (z))  
#define I(x, y, z) ((y) ^ ((x) | (~z)))  
  
//! 将x循环左移n位  
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))  
  
//! 4轮运算中FF(第1轮), GG(第2轮), HH(第3轮), and II(第4轮)转换  

void FF(unsigned int &a,unsigned int b,unsigned int c,unsigned int d,unsigned int x,unsigned int s,unsigned ac)  
{  
    a += F ((b), (c), (d)) + (x) + (unsigned  int)(ac);  
    a = ROTATE_LEFT ((a), (s));  
    a+= (b);  
}  
  
void GG(unsigned int &a,unsigned int b,unsigned int c,unsigned int d,unsigned int x,unsigned int s,unsigned ac)  
{  
    a += G ((b), (c), (d)) + (x) + (unsigned  int)(ac);  
    a = ROTATE_LEFT ((a), (s));  
    a += (b);  
}  
  
void HH(unsigned int &a,unsigned int b,unsigned int c,unsigned int d,unsigned int x,unsigned int s,unsigned ac)  
{  
    a += H ((b), (c), (d)) + (x) + (unsigned  int)(ac);  
    a = ROTATE_LEFT ((a), (s));  
    a+= (b);  
}  
  
void II(unsigned int &a,unsigned int b,unsigned int c,unsigned int d,unsigned int x,unsigned int s,unsigned ac)  
{  
    a += I ((b), (c), (d)) + (x) + (unsigned  int)(ac);  
    a = ROTATE_LEFT ((a), (s));  
    a += (b);  
}  
  
/******************************************************************************/  
//  名称：Encode  
//  功能：数据类型轮换(unsigned  long int -> unsigned char)(未处理前明文的长度转换)  
//  参数：output:  指向unsigned char类型输出缓冲区  
//       input: 指向unsigned long int  
/******************************************************************************/  
void Encode( unsigned char *output, unsigned   int *input, unsigned int len )  
{  
    //unsigned   int为32位，需要转换存到指定char数组中  
    unsigned int i, j;  
    for(i = 0, j = 0; j < len; i++, j += 4)  
    {  
        output[j] =   (unsigned char)(input[i] & 0xff);        //长度的低8位（一个字节）  
        output[j+1] = (unsigned char)((input[i] >> 8) & 0xff); //长度的中间8位  
        output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);//次高8位  
        output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);//高8位  
    }  
}  
  
  
/******************************************************************************/  
//功能：数据类型转换(unsigned char -> unsigned  int)（进行子明文分组（512位分成16组，每组32位））  
//参数： output:   指向unsigned int类型输入缓冲区  
//      input:  指向unsigned char  
/******************************************************************************/  
void Decode( unsigned  int *output, unsigned char *input, unsigned int len )  
{  
    //将明文（char 数组）的每32位为一组存到一个32位的unsigned  int数组中，后面将会用来做运算  
    unsigned int i, j;  
    for( i=0, j=0; j<len; i++, j+=4 )  
    {  
        output[i] = ((unsigned  int)input[j]) | (((unsigned  int)input[j+1]) << 8) |  
                    (((unsigned  int)input[j+2]) << 16) | (((unsigned  int)input[j+3]) << 24);  
    }  
}  
  
/******************************************************************************/  
//  名称：MD5Init  
//  功能：初始链接变量赋值；初始化填充位  
//   参数：指向MD5状态数据变量  
//  返回：无  
//   备注：填充位第1位为1,其余位为0  
  
/******************************************************************************/  
void MD5_Init( MD5_State *s )  
{  
    s->count[0] = s->count[1] = 0;  
    //! 初始链接变量  
    s->state[0] = 0x67452301;  
    s->state[1] = 0xefcdab89;  
    s->state[2] = 0x98badcfe;  
    s->state[3] = 0x10325476;  
      
    //! 初始填充位(目标形式: 0x80000000......，共计512位)  
    memset( s->PADDING, 0, sizeof(s->PADDING) );  
    *(s->PADDING)=0x80;  //第一位为1，其余为0（1000 0000 0000 0000 0000 0000 ....）  
    //  s->PADDING = {  
    //  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  
    //  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  
    //  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };  
}  
  
/******************************************************************************/  
//  名称：MD5Transform  
//  功能：MD5 4轮运算  
//  参数：state: 链接变量；block: 子明文分组  
//  返回：无  
//  备注：4轮共计64步运算  
  
/******************************************************************************/  
void MD5_Transform( unsigned   int state[4], unsigned char block[64] )  
{  
    unsigned  int a = state[0], b = state[1], c = state[2], d = state[3], x[16];  
      
    Decode( x, block, 64 );  //对512位明文分成16组  
      
    //! 第1轮  
      
    FF (a, b, c, d, x[0],  7,  0xd76aa478);  // 1  
    FF (d, a, b, c, x[ 1], 12, 0xe8c7b756);  // 2  
    FF (c, d, a, b, x[ 2], 17, 0x242070db);  // 3  
    FF (b, c, d, a, x[ 3], 22, 0xc1bdceee);  // 4  
    FF (a, b, c, d, x[ 4], 7,  0xf57c0faf);  // 5  
    FF (d, a, b, c, x[ 5], 12, 0x4787c62a);  // 6  
    FF (c, d, a, b, x[ 6], 17, 0xa8304613);  // 7  
    FF (b, c, d, a, x[ 7], 22, 0xfd469501);  // 8  
    FF (a, b, c, d, x[ 8], 7,  0x698098d8);  // 9  
    FF (d, a, b, c, x[ 9], 12, 0x8b44f7af);  // 10  
    FF (c, d, a, b, x[10], 17, 0xffff5bb1);  // 11  
    FF (b, c, d, a, x[11], 22, 0x895cd7be);  // 12  
    FF (a, b, c, d, x[12], 7,  0x6b901122);  // 13  
    FF (d, a, b, c, x[13], 12, 0xfd987193);  // 14  
    FF (c, d, a, b, x[14], 17, 0xa679438e);  // 15  
    FF (b, c, d, a, x[15], 22, 0x49b40821);  // 16  
      
    //! 第2轮  
    GG (a, b, c, d, x[ 1], 5,  0xf61e2562);  // 17  
    GG (d, a, b, c, x[ 6], 9,  0xc040b340);  // 18  
    GG (c, d, a, b, x[11], 14, 0x265e5a51);  // 19  
    GG (b, c, d, a, x[ 0], 20, 0xe9b6c7aa);  // 20  
    GG (a, b, c, d, x[ 5], 5,  0xd62f105d);  // 21  
    GG (d, a, b, c, x[10], 9,  0x2441453);   // 22  
    GG (c, d, a, b, x[15], 14, 0xd8a1e681);  // 23  
    GG (b, c, d, a, x[ 4], 20, 0xe7d3fbc8);  // 24  
    GG (a, b, c, d, x[ 9], 5,  0x21e1cde6);  // 25  
    GG (d, a, b, c, x[14], 9,  0xc33707d6);  // 26  
    GG (c, d, a, b, x[ 3], 14, 0xf4d50d87);  // 27  
    GG (b, c, d, a, x[ 8], 20, 0x455a14ed);  // 28  
    GG (a, b, c, d, x[13], 5,  0xa9e3e905);  // 29  
    GG (d, a, b, c, x[ 2], 9,  0xfcefa3f8);  // 30  
    GG (c, d, a, b, x[ 7], 14, 0x676f02d9);  // 31  
    GG (b, c, d, a, x[12], 20, 0x8d2a4c8a);  // 32  
      
    //! 第3轮  
    HH (a, b, c, d, x[ 5], 4,  0xfffa3942);  // 33  
    HH (d, a, b, c, x[ 8], 11, 0x8771f681);  // 34  
    HH (c, d, a, b, x[11], 16, 0x6d9d6122);  // 35  
    HH (b, c, d, a, x[14], 23, 0xfde5380c);  // 36  
    HH (a, b, c, d, x[ 1], 4,  0xa4beea44);  // 37  
    HH (d, a, b, c, x[ 4], 11, 0x4bdecfa9);  // 38  
    HH (c, d, a, b, x[ 7], 16, 0xf6bb4b60);  // 39  
    HH (b, c, d, a, x[10], 23, 0xbebfbc70);  // 40  
    HH (a, b, c, d, x[13], 4,  0x289b7ec6);  // 41  
    HH (d, a, b, c, x[ 0], 11, 0xeaa127fa);  // 42  
    HH (c, d, a, b, x[ 3], 16, 0xd4ef3085);  // 43  
    HH (b, c, d, a, x[ 6], 23, 0x4881d05);   // 44  
    HH (a, b, c, d, x[ 9], 4,  0xd9d4d039);  // 45  
    HH (d, a, b, c, x[12], 11, 0xe6db99e5);  // 46  
    HH (c, d, a, b, x[15], 16, 0x1fa27cf8);  // 47  
    HH (b, c, d, a, x[ 2], 23, 0xc4ac5665);  // 48  
      
    //! 第4轮  
    II (a, b, c, d, x[ 0], 6,  0xf4292244);  // 49  
    II (d, a, b, c, x[ 7], 10, 0x432aff97);  // 50  
    II (c, d, a, b, x[14], 15, 0xab9423a7);  // 51  
    II (b, c, d, a, x[ 5], 21, 0xfc93a039);  // 52  
    II (a, b, c, d, x[12], 6,  0x655b59c3);  // 53  
    II (d, a, b, c, x[ 3], 10, 0x8f0ccc92);  // 54  
    II (c, d, a, b, x[10], 15, 0xffeff47d);  // 55  
    II (b, c, d, a, x[ 1], 21, 0x85845dd1);  // 56  
    II (a, b, c, d, x[ 8], 6,  0x6fa87e4f);  // 57  
    II (d, a, b, c, x[15], 10, 0xfe2ce6e0);  // 58  
    II (c, d, a, b, x[ 6], 15, 0xa3014314);  // 59  
    II (b, c, d, a, x[13], 21, 0x4e0811a1);  // 60  
    II (a, b, c, d, x[ 4], 6,  0xf7537e82);  // 61  
    II (d, a, b, c, x[11], 10, 0xbd3af235);  // 62  
    II (c, d, a, b, x[ 2], 15, 0x2ad7d2bb);  // 63  
    II (b, c, d, a, x[ 9], 21, 0xeb86d391);  // 64  
      
    state[0] += a;  
    state[1] += b;  
    state[2] += c;  
    state[3] += d;  
      
    memset( (unsigned char*)x, 0, sizeof (x) );  
}  
  
/******************************************************************************/  
//  名称：MD5_Update  
//  功能：明文填充，明文分组，16个子明文分组  
//  参数：指向SHA状态变量  
//  返回：无  
  
/******************************************************************************/  
void MD5_Update( MD5_State *s, unsigned char *input, unsigned int inputLen )  
{  
    unsigned int i, index, partLen;  
      
    //! 明文填充  
      
    //! 字节数 mod 64（当前拥有的明文字节数）  
    index = (unsigned int)((s->count[0] >> 3) & 0x3F);//一个字符一个字节占8位（count里面存的是位数，所以需要转换为字节数）  
    //index = (unsigned int)((s->count[0] >> 3)%64);  
      
    //! 更新位数  
    if((unsigned long int)(s->count[0] += ((unsigned long int)inputLen <<3))< ((unsigned long int)inputLen << 3))//inputLen是字节数，转换为位数比较  
    {  
        //发生溢出，则需要进位(无符号数其Max值+1==0)  
        s->count[1]++; //进位  
    }  
    s->count[1] += ((unsigned  int)inputLen >> 29);    //输入的高位字节数 inputlen*8 >> 32  
    partLen = 64 - index; //还差的明文字节数  
      
    //! MD5 4轮运算  
    if (inputLen >= partLen) //如果明文字符串长度能提供还差的字符长度，则继续执行  
    {  
        memcpy( (unsigned char*)&s->buffer[index],  (unsigned char*)input, partLen ); //将还差的明文拷到缓冲区，等待处理  
        MD5_Transform( s->state, s->buffer );   //处理  
          
        for( i = partLen; i + 63 < inputLen; i += 64 ) //查找是否存在下一个64字节的明文  
            MD5_Transform( s->state, &input[i] );      //有则继续处理  
          
        index = 0;  
    }  
    else  
        i = 0;  
      
    memcpy ((unsigned char*)&s->buffer[index], (unsigned char*)&input[i], inputLen-i); //对不够64字节的明文字符串，先拷到缓冲区等待构建完整的512位明文  
}  
  
/******************************************************************************/  
//  名称：MD5_Final  
//  功能：MD5最后变换  
//  参数：strContent:指向文件内容缓冲区; iLength:文件内容长度; output:摘要输出缓冲区  
//  返回：无  
  
/******************************************************************************/  
void MD5_Final( MD5_State *s, unsigned char digest[16] )  
{  
    unsigned char bits[8];      //记录未处理前的明文的长度  
    unsigned int index, padLen;  
      
    Encode (bits, s->count, 8); //将未处理前的明文长度转换到bits数组中  
      
    //! 长度小于448位(mod 512（64个字节）),对明文进行填充(448位为56个字节)  
    index = (unsigned int)((s->count[0] >> 3) & 0x3f);   //计算已有的位数  
    padLen = (index < 56) ? (56 - index) : (120 - index);//补充说明（5）(计算还差的位数 64-index+56=120-index)  
    MD5_Update( s, s->PADDING, padLen );                 //填充还差位数的明文  
      
    MD5_Update( s, bits, 8);         //加入未处理前的明文的长度  
    Encode( digest, s->state, 16 );  //将MD5摘要转换到输出缓冲区里  
      
    //初始化到最开始的状态，处理下一个明文  
    memset ((unsigned char*)s, 0, sizeof (*s));  
    MD5_Init( s );  
}  
  
  
/******************************************************************************/  
//  名称：SHA_digest  
//  功能：生成文件摘要  
//  参数：strContent:指向文件内容缓冲区; iLength:文件内容长度; output:摘要输出缓冲区  
//  返回：无  
  
/******************************************************************************/  
void md5_digest( void const *strContent, unsigned int iLength, unsigned char output[16] )  
{  
    unsigned char *q = (unsigned char*)strContent;  
    MD5_State s;  
    MD5_Init( &s );               //初始化MD5状态数据结构  
    MD5_Update( &s, q, iLength ); //处理64*n个字节的明文，对每512位的明文进行处理（有可能没有64个字节）  
    MD5_Final( &s, output );      //处理最后需要填充的明文  
}



int main( int argc, char **argv )  
{  
    unsigned char buff[16];  
  //  unsigned int x=4294967295;  
  //  printf("%u\n",(unsigned int)(x+1));  
      
    //需加密的明文

    for(int i=0;i<1;i++)  
    {  
        md5_digest(argv[1],(unsigned int)strlen(argv[1]),buff);  
        printf("MD5(%s) = \n",argv[1]);     
        //MD5摘要是128位，以16进制的形式输出  
        for(int j=0;j<16;j++)  
        {  
            printf("%x",(buff[j] & 0xF0)>>4);  
            printf("%x",buff[j] & 0x0F);  
        }  
        printf("\n\n");  
    }  
    return 0;  
}  
