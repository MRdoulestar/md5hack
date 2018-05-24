# -*- coding: utf-8 -*-
import my_md5
import sys
import six
MD5_Hash=sys.argv[1]
length=int(sys.argv[2])
text=sys.argv[3]

s1=eval('0x'+MD5_Hash[:8].decode('hex')[::-1].encode('hex'))
s2=eval('0x'+MD5_Hash[8:16].decode('hex')[::-1].encode('hex'))
s3=eval('0x'+MD5_Hash[16:24].decode('hex')[::-1].encode('hex'))
s4=eval('0x'+MD5_Hash[24:32].decode('hex')[::-1].encode('hex'))

secret = "a"*length
test=secret+'\x80'+'\x00'*((512-length*8-8-8*8)/8)+six.int2byte(length*8)+'\x00\x00\x00\x00\x00\x00\x00'+text
s = my_md5.deal_rawInputMsg(test)
r = my_md5.deal_rawInputMsg(secret)
inp = s[len(r):]
print '填充完的数据为:'+test+'\n'
print '----------------------------------------------------------'
print '扩充完的数据为(16进制):'+s
print '----------------------------------------------------------'
print '截取最后分组的数据(16进制):'+inp
print '----------------------------------------------------------'

print  '最终填充结果为:'+bytes(test).encode('hex')
print "填充后的md5为:"+my_md5.run_md5(s1,s2,s3,s4,inp)
