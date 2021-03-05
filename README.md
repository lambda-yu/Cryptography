# Cryptography
一些常用加密方法的python实现 和 golang实现
以及python调用的golang方法

### python调用goalng构建方法

```shell script
$ go build -buildmode=c-shared -o XXXXXX.so XXXXXX.go
```

```python
from ctypes import cdll
# 导入模块
# lib = CDLL('./XXXXXX.so')
lib = cdll.LoadLibrary('./XXXXXX.so')

# 调用模块中的函数
result = lib.add(2, 3)
```