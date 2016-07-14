# mailbrute
================
## Lib安装：

####     easy_install threadpool

===============
## Notes：

* 使用poplib3模块破解邮箱
* 多线程
* 支持用户名和密码字典中一一对应或所有组合的破解
* mailbrute.py -h 参数可以查看各参数的用法

===============
## Usage：

* mailbrute.py [Options]
	* -U  <用户名字典文件> (需放在mailbrute.py同目录下)
	* -P  <密码字典文件>   (需放在mailbrute.py同目录下)
	* -s  <完整的POP服务器域名>，例如：pop.163.com
	* -p  服务器端口，如：110，995
	* -t  线程数，默认为10
	* -d  延迟时间，默认0.5秒，防止服务器堵塞，漏报
	* -E  自动从用户名字典中提取@后面的域名作为pop服务器爆破
* 示例1：

#### mailbrute.py -U user.txt -P pass.txt -s pop.163.com -p 110
* 示例2：

#### mailbrute.py -U user.txt -P pass.txt -p 110 -E 

