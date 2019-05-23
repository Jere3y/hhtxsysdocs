## 开发建议

合和天下所有接口都是 https 协议，证书出自正规 CA 签发。**建议请求的时进行证书验证。**
   
## 签名作用

1. 传输中，防篡改。
   
2. 给合和天下服务器，确定身份。

## 需要准备的参数

| 参数名     | 说明                                   | 来源                 | 类型   | 示例        |
| ---------- | -------------------------------------- | -------------------- | ------ | ----------- |
| tim        | 当前时间戳，以秒为单位的整数**字符串** | 自己获取             | 字符串 | - |
| alg        | 签名算法                               | 固定参数             | 字符串 | HS256       |
| uid        | uid                                    | 申请开发者账号后获取 | 字符串 | -           |
| client_key | 签名算法的密码(客户端，请求时用)       | 申请开发者账号后获取 | 字符串 | -           |
| server_key | 签名算法的密码(服务端，接收响应时验证) | 申请开发者账号后获取 | 字符串 | -           |

## 签名算法

1. 头信息： headerStr={"uid": "123456", "tim": "1558079861", "alg": "HS256"}，请使用标准的 JSON 字符串格式。服务器会严格校验格式。tim 参数请取当前时间戳，为整数字符串。

2. 请求 body 信息（POST 方法有，GET 方法为空）bodyStr 

3. sign = hmacSHA256((headerStr + bodyStr), key)，hmacSha256 的算法下面有示例

4. auth = base64encode(headerStr) + "." + sign
 
5. 将 auth 放在 HTTP Authorization 头信息中(注意 Bearer 后有一个空格)，如下：
   
        Authorization: Bearer auth

6. 系统暂时只支持 HS256 算法，具体实现示例如下。

## 签名算法示例

### PHP

    $s = hash_hmac('sha256', 'Message', 'secret', true);
    echo base64_encode($s);

### JAVA

    import javax.crypto.Mac;
    import javax.crypto.spec.SecretKeySpec;
    import org.apache.commons.codec.binary.Base64;

    public class ApiSecurityExample {
        public static void main(String[] args) {
            try {
                String secret = "secret";
                String message = "Message";

                Mac sha256HMAC = Mac.getInstance("HmacSHA256");
                SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
                sha256HMAC.init(secretKey);

                String hash = Base64.encodeBase64String(sha256HMAC.doFinal(message.getBytes()));
                System.out.println(hash);
            }
            catch (Exception e){
               System.out.println("Error");
            }
        }
    }

### C# #

    using System.Security.Cryptography;

    namespace Test
    {
        public class MyHmac
        {
            private string CreateToken(string message, string secret)
            {
                secret = secret ?? "";
                var encoding = new System.Text.ASCIIEncoding();
                byte[] keyByte = encoding.GetBytes(secret);
                byte[] messageBytes = encoding.GetBytes(message);
                using (var hmacsha256 = new HMACSHA256(keyByte))
                {
                    byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                    return Convert.ToBase64String(hashmessage);
                }
            }
        }
    }

### Python 3

    import hashlib
    import hmac
    import base64

    message = bytes('Message', 'utf-8')
    secret = bytes('secret', 'utf-8')

    signature = base64.b64encode(hmac.new(secret, message, digestmod=hashlib.sha256).digest())
    print(signature)

### Go 

    package main

    import (
        "crypto/hmac"
        "crypto/sha256"
        "encoding/base64"
        "fmt"
    )

    func ComputeHmac256(message string, secret string) string {
        key := []byte(secret)
        h := hmac.New(sha256.New, key)
        h.Write([]byte(message))
        return base64.StdEncoding.EncodeToString(h.Sum(nil))
    }

    func main() {
        fmt.Println(ComputeHmac256("Message", "secret"))
    }