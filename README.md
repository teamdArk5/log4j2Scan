# log4j2Scan
 对pmiaowu的作品新增自定义dnslog平台

config.yml配置：
`other: "token=admin;Identifier=admin1.log.dark5.net;dnslogDomainName=ns.dark5.net:8000;"`

Identifier：指你的dnslog域名
dnslogDomainName：指你dnslog平台的地址

**注意！**
需要配合修改后的[DNSlog-GO](https://github.com/lanyi1998/DNSlog-GO)使用，懒得自己编译的我已经给出我编译好linux-amd64版本的。
```golang
func verifyDns(w http.ResponseWriter, r *http.Request) {
	Dns.DnsDataRwLock.RLock()
	defer Dns.DnsDataRwLock.RUnlock()
	var Q queryInfo
	key := r.Header.Get("token")
	if Core.VerifyToken(key) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &Q)
		resp := RespData{
			HTTPStatusCode: "200",
			Msg:            "false",
		}
		for _, v := range Dns.DnsData[key] {
			//if v.Subdomain == Q.Query {
			if strings.Contains(v.Subdomain, Q.Query) {  //这里改成包含就返回true
				resp.Msg = "true"
				break
			}

		}
		fmt.Fprint(w, JsonRespData(resp))
	} else {
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "403",
			Msg:            "false",
		}))
	}
}
```

dnslog-go的配置文件config.yaml
```
HTTP:
  port: 8000
  #{"token":"用户对应子域名"}
  user: { "admin": "admin1" } # admin为token，admin1是admin的子域，可以随意设定。
  consoleDisable: false
Dns:
  domain: log.dark5.net
```

