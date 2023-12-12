# hci-api-proxy

HCI api请求前需要先获取token，并且token定时更换，无法用zabbix的http client获取并监控，因此使用此程序作为代理，实现监控功能。

### 功能
- 检查HCI API是否可达
- 支持配置


### 运行
需要配置，代码中有部分硬编码，需要根据实际调整。
> go mod init hci-api-proxy
> go run app.go 

