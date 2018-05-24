#MD5拓展攻击辅助工具

#为解决python不同于c的传参问题
S=[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
s=[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

#左移
def ROTATE_LEFT(x,n):
    return (((x) << (n)) | ((x) >> (32-(n))))

def F(x,y,z):
    return (((x) & (y)) | ((~x) & (z)))
def G(x,y,z):
    return (((x) & (z)) | ((y) & (~z)))
def H(x,y,z):
    return ((x) ^ (y) ^ (z))
def I(x,y,z):
    return ((y) ^ ((x) | (z)))

#abcd为链接变量,m为传入的16位明文分组
def FF(real,a,b,c,d,m,shift,vec):
    real[a] += F(real[b], real[c], real[d]) + m + vec
    real[a] = ROTATE_LEFT(real[a], shift)
    real[a] += real[b]

def GG(real,a,b,c,d,m,shift,vec):
    real[a] += G(real[b], real[c], real[d]) + m + vec
    real[a] = ROTATE_LEFT(a, shift)
    real[a] += real[b]

def HH(real,a,b,c,d,m,shift,vec):
    real[a] += H(real[b], real[c], real[d]) + m + vec
    real[a] = ROTATE_LEFT(a, shift)
    real[a] += real[b]

def II(real,a,b,c,d,m,shift,vec):
    real[a] += I(real[b], real[c], real[d]) + m + vec
    real[a] = ROTATE_LEFT(a, shift)
    real[a] += real[b]






#M=[0x6162, 0x6380] + [0x00]*26 + [0x1800, 0x00, 0x00, 0x00]
M=[0]*16
a,b,c,d=S[0],S[1],S[2],S[3]
#x为16个明文分组，数字为左移位数
FF (S,0, 1, 2, 3, M[0],  7,  0xd76aa478) 
FF (S,3, 0, 1, 2, M[1], 12, 0xe8c7b756) 
FF (S,2, 3, 0, 1, M[2], 17, 0x242070db) 
FF (S,1, 2, 3, 0, M[3], 22, 0xc1bdceee) 
FF (S,0, 1, 2, 3, M[4], 7,  0xf57c0faf) 
FF (S,3, 0, 1, 2, M[5], 12, 0x4787c62a) 
FF (S,2, 3, 0, 1, M[6], 17, 0xa8304613) 
FF (S,1, 2, 3, 0, M[7], 22, 0xfd469501) 
FF (S,0, 1, 2, 3, M[8], 7,  0x698098d8) 
FF (S,3, 0, 1, 2, M[9], 12, 0x8b44f7af)  
FF (S,2, 3, 0, 1, M[10], 17, 0xffff5bb1)  
FF (S,1, 2, 3, 0, M[11], 22, 0x895cd7be)  
FF (S,0, 1, 2, 3, M[12], 7,  0x6b901122)  
FF (S,3, 0, 1, 2, M[13], 12, 0xfd987193)  
FF (S,2, 3, 0, 1, M[14], 17, 0xa679438e)  
FF (S,1, 2, 3, 0, M[15], 22, 0x49b40821)  
  
GG (S,0, 1, 2, 3, M[1], 5,  0xf61e2562)  
GG (S,3, 0, 1, 2, M[6], 9,  0xc040b340)  
GG (S,2, 3, 0, 1, M[11], 14, 0x265e5a51)  
GG (S,1, 2, 3, 0, M[0], 20, 0xe9b6c7aa)  
GG (S,0, 1, 2, 3, M[5], 5,  0xd62f105d)  
GG (S,3, 0, 1, 2, M[10], 9,  0x02441453)  
GG (S,2, 3, 0, 1, M[15], 14, 0xd8a1e681)  
GG (S,1, 2, 3, 0, M[4], 20, 0xe7d3fbc8)  
GG (S,0, 1, 2, 3, M[9], 5,  0x21e1cde6)  
GG (S,3, 0, 1, 2, M[14], 9,  0xc33707d6)  
GG (S,2, 3, 0, 1, M[3], 14, 0xf4d50d87)  
GG (S,1, 2, 3, 0, M[8], 20, 0x455a14ed)  
GG (S,0, 1, 2, 3, M[13], 5,  0xa9e3e905)  
GG (S,3, 0, 1, 2, M[2], 9,  0xfcefa3f8)  
GG (S,2, 3, 0, 1, M[7], 14, 0x676f02d9)  
GG (S,1, 2, 3, 0, M[12], 20, 0x8d2a4c8a)  
  
HH (S,0, 1, 2, 3, M[5], 4,  0xfffa3942)  
HH (S,3, 0, 1, 2, M[8], 11, 0x8771f681)  
HH (S,2, 3, 0, 1, M[11], 16, 0x6d9d6122)  
HH (S,1, 2, 3, 0, M[14], 23, 0xfde5380c)  
HH (S,0, 1, 2, 3, M[1], 4,  0xa4beea44)  
HH (S,3, 0, 1, 2, M[4], 11, 0x4bdecfa9)  
HH (S,2, 3, 0, 1, M[7], 16, 0xf6bb4b60)  
HH (S,1, 2, 3, 0, M[10], 23, 0xbebfbc70)  
HH (S,0, 1, 2, 3, M[13], 4,  0x289b7ec6)  
HH (S,3, 0, 1, 2, M[0], 11, 0xeaa127fa)  
HH (S,2, 3, 0, 1, M[3], 16, 0xd4ef3085)  
HH (S,1, 2, 3, 0, M[6], 23, 0x04881d05)  
HH (S,0, 1, 2, 3, M[9], 4,  0xd9d4d039)  
HH (S,3, 0, 1, 2, M[12], 11, 0xe6db99e5)  
HH (S,2, 3, 0, 1, M[15], 16, 0x1fa27cf8)  
HH (S,1, 2, 3, 0, M[2], 23, 0xc4ac5665)  
  
II (S,0, 1, 2, 3, M[0], 6,  0xf4292244)  
II (S,3, 0, 1, 2, M[7], 10, 0x432aff97)  
II (S,2, 3, 0, 1, M[14], 15, 0xab9423a7)  
II (S,1, 2, 3, 0, M[5], 21, 0xfc93a039)  
II (S,0, 1, 2, 3, M[12], 6,  0x655b59c3)  
II (S,3, 0, 1, 2, M[3], 10, 0x8f0ccc92)  
II (S,2, 3, 0, 1, M[10], 15, 0xffeff47d)  
II (S,1, 2, 3, 0, M[1], 21, 0x85845dd1)  
II (S,0, 1, 2, 3, M[8], 6,  0x6fa87e4f)  
II (S,3, 0, 1, 2, M[15], 10, 0xfe2ce6e0)  
II (S,2, 3, 0, 1, M[6], 15, 0xa3014314)  
II (S,1, 2, 3, 0, M[13], 21, 0x4e0811a1)  
II (S,0, 1, 2, 3, M[4], 6,  0xf7537e82)  
II (S,3, 0, 1, 2, M[11], 10, 0xbd3af235)  
II (S,2, 3, 0, 1, M[2], 15, 0x2ad7d2bb)  
II (S,1, 2, 3, 0, M[9], 21, 0xeb86d391)

s[0] += S[0]
s[1] += S[1]
s[2] += S[2]
s[3] += S[3]

#print(M)
for i in s:
    print(hex(i).replace('0x',''))
print()
