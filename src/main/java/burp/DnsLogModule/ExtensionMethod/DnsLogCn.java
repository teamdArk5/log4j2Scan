package burp.DnsLogModule.ExtensionMethod;

import java.io.PrintWriter;

import burp.Bootstrap.CustomHelpers;
import burp.Bootstrap.YamlReader;
import com.github.kevinsawicki.http.HttpRequest;

import burp.IBurpExtenderCallbacks;
import burp.DnsLogModule.ExtensionInterface.DnsLogAbstract;

public class DnsLogCn extends DnsLogAbstract {
    private IBurpExtenderCallbacks callbacks;

    private String dnslogDomainName;

    private YamlReader yamlReader;

    private String key;
    private String token;
    private String Identifier;

    public DnsLogCn(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        //this.dnslogDomainName = "http://192.168.5.160:81";
        //this.dnslogDomainName = "http://dnslog.cn";

        this.setExtensionName("DnsLogCn");

        this.yamlReader = YamlReader.getInstance(callbacks);
        String other = this.yamlReader.getString("dnsLogModule.other");

        //this.key = CustomHelpers.randomStr(8);
        this.key = CustomHelpers.randomStr(8);
        this.token = CustomHelpers.getParam(other, "token").trim();
        this.Identifier = CustomHelpers.getParam(other, "Identifier").trim();  // admin1.log.dark5.net
        this.dnslogDomainName = CustomHelpers.getParam(other, "dnslogDomainName").trim();

        this.init();
    }

    private void init() {
        if (this.token == null || this.token.length() <= 0) {
            throw new RuntimeException(String.format("%s 扩展-token参数不能为空", this.getExtensionName()));
        }
        if (this.Identifier == null || this.Identifier.length() <= 0) {
            throw new RuntimeException(String.format("%s 扩展-Identifier参数不能为空", this.getExtensionName()));
        }

        String temporaryDomainName = this.key +"."+ this.Identifier;
        this.setTemporaryDomainName(temporaryDomainName);
    }

    @Override
    public String getBodyContent() {
        String url = String.format("http://%s/api/verifyDns",this.dnslogDomainName.trim());
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";
        // JSON数据
        String jsonInputString = String.format("{\"Query\": \"%s\"}",this.key);
        HttpRequest request = new HttpRequest(url,"POST");
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
        request.header("token", this.token.trim());
        request.readTimeout(30 * 1000);
        request.connectTimeout(30 * 1000);

        request.contentType("application/json").send(jsonInputString);

        String body = request.body();

        if (!request.ok()) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-%s内容有异常,异常内容: %s",
                            this.getExtensionName(),
                            this.dnslogDomainName,
                            body
                    )
            );
        }

        if (body.contains("false")) {
            return null;
        }
        return body;
    }

    @Override
    public String export() {
        String str1 = String.format("<br/>============dnsLogExtensionDetail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("dnsLogDomainName: %s <br/>", this.dnslogDomainName);
        String str4 = String.format("dnsLogRecordsApi: %s <br/>", this.dnslogDomainName + "/getrecords.php");
        //String str5 = String.format("cookie: %s=%s <br/>", this.dnsLogCookieName, this.dnsLogCookieValue);
        String str6 = String.format("dnsLogTemporaryDomainName: %s <br/>", this.getTemporaryDomainName());
        String str7 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4  + str6 + str7;

        return detail;
    }

    @Override
    public void consoleExport() {
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========dnsLog扩展详情===========");
        stdout.println("你好呀~ (≧ω≦*)喵~");
        stdout.println(String.format("被调用的插件: %s", this.getExtensionName()));
        stdout.println(String.format("dnsLog域名: %s", this.dnslogDomainName));
        stdout.println(String.format("dnsLog保存记录的api接口: %s", this.dnslogDomainName + "/getrecords.php"));
        //stdout.println(String.format("cookie: %s=%s", this.dnsLogCookieName, this.dnsLogCookieValue));
        stdout.println(String.format("dnsLog临时域名: %s", this.getTemporaryDomainName()));
        stdout.println("===================================");
        stdout.println("");
    }
}
