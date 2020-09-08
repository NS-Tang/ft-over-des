# ft-over-des
分了两次项目做，先实现DES算法，然后实现文件服务器。
## DES算法部分
主要说说我和标准文件的算法略有不同地方的和一些实现算法应用必须的额外的东西。

首先是我的程序使用了二进制打开文件，适用于任何格式文件或数据的加密解密。
在代码中尽量多使用位操作以提高效率。

由于很多函数在代码中的调用位置只有一处或不多的几处，所以所有函数均inline。

KS，这个在标准文件的算法中是每次迭代解密的时候调用一次，实际肯定不能这样，否则调用的时候KS内部又得替换当前迭代轮数那么多次，时间复杂度O(n^2)。我一开始想可以随着加密迭代替换，但那样反向的就不行，还是要O(n^2)。所以考虑直接一次性生成所有K密钥组，再后来发现这个过程完全可以在加密前进行，整个文件加密过程都用这些生成好的K密钥组。对于单块加密或解密来说时间复杂度变成了O(1)。

由于算法中多次用到数据根据数组按位替换的运算，于是写成函数。

S，这在给的算法中是一组算法，实际上还是会先后执行，除非多线程，否则一般是考虑迭代执行S1-S8，并且随着B集合的右移与需要的位置对齐取位。这里我没有每次一下移6位而是：
* 先令 B的第1位与i的第1位对齐取位，
* 然后右移1位令B的第2-5位与j的1-4位对齐取位，
* 再右移3位令B的第6位与i的第2位对齐取位，
* 再右移2位进入下一次迭代。
* 移位3次解决问题

如果不这样向同一个方向一点点对齐着移位的话，每次迭代除了要右移一次6位外，每个取位由于需要对齐还要把某个变量移位一或几次，要移4次或更多，并且可能多一堆临时变量。
同时8个映射数组也放到了一个数组里，方便迭代。

我把加密和解密写成一个函数，是因为它们除了迭代中对密钥组的调用的顺序相反以外，是完全等价的。标准文件的算法中它们两个的LR是完全反过来的，而给的算法中的n也只是为了指示本轮迭代L和R对应的密钥，n写在L和R上没有实际意义。至于带撇不带撇，给的算法中好像有一种不带撇在先带撇在后的意味：
> L' = R  
> R' = L ^ f(R,K)  
> R = L'  
> L = R' ^ f(L',K)

然而在实际写成函数（注释中保留了解密函数）之后发现没有任何区别，实际上赋值号左边的是由右边的生成，时间上一定在右边的之后。

这样也就是说我如果把解密的L重命名成R，R重命名成L，忽略掉L和R的下标，除了调用K的地方，这两个算法完全相同。因此只需指定其对密钥的调用顺序即可确定是加密还是解密。
## 网络传输部分
本次项目我稍微改动了一下之前的DES算法，改动主要有下：
首先是由于本次项目不是单纯直接对文件加密解密，所以把有关文件加密的函数取消了，只留了public权限的两个函数KS和cipher_block，如前次所述KS与密钥直接相关，所以用密钥时生成一次KS即可，时间上应与块加密分开。对于本次项目来说更为明显，由于服务器端只需输入一次密钥，用于加密多个文件，KS的作用域可以扩展到多个文件。
* 取消了类的成员变量，基本上起不到多大作用甚至影响效率。影响效率的原因是有些类成员变量实际上编译时即可确定值，对于inline函数来说会被直接替换为常量，设计为变量则必须运行时计算。比如加密方向函数的方向参数。这样可以省去函数加密时的K起始位置和遍历方向计算开销。
* left_shift本来是参数用作输出的，我觉得不太清晰，改为返回值用作输出。
* KS算法，由KEY生成K，多一个输出函参K。
* cipher_block，多两个输入函参K和direction，原因见上。

其余private函数没有变。

然后说一下服务器端和用户端的设计：
errexit.c passivesock.c passiveTCP.c connectsock.c connectTCP.c这些库代码用的是之前网络通讯程序设计课老师给的，用途是生成tcp连接。其中passivesock进行到listen，connectsock进行到connect。
以下对流程的描述中，对某个流程的时间描述均以完成时间为准，比如阻塞的函数以它执行完毕的时间为准。对于服务器端，只针对它的一个循环。流程如下：
 
0. 整个使用流程是首先启动服务器端，输入密钥（一定要服务器端先输入密钥才可以启动客户端），设计为启动后输入是我考虑到命令行会存储命令日志。我的设计是输入密钥后立即转换为K密钥组并释放密钥KEY（运用代码块），目的是尽可能的少让KEY在内存中存储，以防泄密，不知道有没有用，但没什么副作用还能减少运行时内存使用。不过理论上通过K应该可以还原KEY，这里用处不大。
1. 客户端请求链接，服务器端响应连接。
2. 客户端发送源文件（请求的文件，在服务器上）路径长度；服务器端分配字符串大小。
3. 客户端再发送源文件路径；服务器端打开此文件（出错进入下一个循环）。
4. 服务器端发送文件大小；客户端依此分配缓冲区（向上取整）。
5. 服务器端加密文件（向上取整的整块）；客户端收取加密文件，输入密钥，整块解密后把文件大小的部分写入目的文件（本地）。

这里客户端在解密时才要求输入密钥，输入密钥之后即时生成K，然后即时解密，解密完即时释放KEY和K，切实达到让密钥和K在内存里少跑的效果。
另外由于传输了确切文件大小，这里做到了向上取整对全部块的完美加密解密。

服务器端主函数不停运行，也有完整的错误提示，但是服务器端建立socket成功后不会有错误使程序退出，只是进入输出错误并进入下一个循环，不断接受客户端的请求，并打印被请求文件的记录，直至手动关闭。
客户端主函数依然仿照Linux下的cp命令进行命令行设计，出错提示等。并提供了成功提示。