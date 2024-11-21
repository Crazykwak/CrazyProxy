## 버전정보
java17 로 만들었는데, 뭐 1.8에서도 작동은 하지 않을까 싶음

## 실행방법

### -D옵션

-Dorg.crazyproxy.config.SSLConfig.TLS.version=TLSv1.3  <-- 디폴트가 1.3임  
-Dorg.crazyproxy.properties=main.yaml  

org.crazyproxy.properties 는 yaml, properties, json이 가능함.

jar 말아서 java로 실행 ㄱ

## 프로퍼티 작성법

#### 필수값
```text
mappingFilePath : port : target 으로 이루어진 파일 패스. properties 문법을 따름
```

#### 디폴트
```text
keyFilePath = null <-- 사실상 쓸 일 없음. 나중에 HTTPS로 서버 띄울때나 쓸 듯
trustFilePath = null <-- 이 값이 null일 경우 모든 인증서를 신뢰한다.
workerCount = 50
bufferSize = 100kb
```
### 작성 예시
#### properties
```properties
mappingFilePath=mapping.properties
keyFilePath=proxy.jks
keyFactoryPassword=changeit
keyPassword=changeit
trustFilePath=cacerts
trustPassword=changeit
workerCount=40
bufferSize=100kb
```

#### yaml
```yaml
mappingFilePath: mapping.properties
workerCount: 40
bufferSize: 100kb
```

#### Json
```json
{
  "mappingFilePath" : "mapping.properties",
  "workerCount": 40,
  "bufferSize": "100kb"
}
```

## mapping.properties 작성법
```properties
8001=http://localhost:8081
8002=https://naver.com
8004=https://www.daum.net/
8005=https://google.com
```

## Contact Me
kwj1830@naver.com