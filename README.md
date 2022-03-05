Exploiting CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user 

Adding the **sam_the_admin_maq** when **MachineAccountQuota=0**


#### 改动
在原项目：[sam-the-admin](https://github.com/WazeHell/sam-the-admin)中，maq等于0也就是域用户没有权限添加机器用户的时候无法进行利用

在当前项目添加了maq为0时的自动化利用，通过获取域用户修改已存在的机器用户samname进行利用

在脚本中已加入自动修改机器用户的ntlm功能以获取TGT，并在利用完成后对机器用户的ntlm和spn自动进行恢复

> 在进行ntlm恢复的时候需要手动输入机器用户的IP

#### Usage
maq为0

<img width="403" alt="image" src="https://user-images.githubusercontent.com/49117752/156877505-c8b1b262-941f-4fa6-a264-94f49ad427bc.png">

使用原版的exp无法进行利用

<img width="1058" alt="image" src="https://user-images.githubusercontent.com/49117752/156877556-c3aa9efb-8fbf-4826-8d76-d7103ca4dd14.png">

通过sam-the-admin-maq自动化利用

[![asciicast](https://asciinema.org/a/FoCV2OVZIuQ3zoRTwAEzPKzgO.svg)](https://asciinema.org/a/FoCV2OVZIuQ3zoRTwAEzPKzgO)

#### Check out 
- [CVE-2021-42287/CVE-2021-42278 Weaponisation ](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
- [sAMAccountName spoofing](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)
