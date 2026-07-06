content: ## site-local.zeek — Config local de Zeek para KhaiNet
## Activa los scripts de análisis relevantes para NDR

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/files
@load base/protocols/ftp
@load base/protocols/smtp

# Detección de anomalías
@load base/frameworks/notice
@load base/frameworks/signatures
@load base/frameworks/intel
@load policy/frameworks/notice/do-notice
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/dns/detect-external-names
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssh/interesting-hostnames
@load policy/misc/scan
@load policy/misc/probe-creator
@load policy/integration/collective-intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

# Logging en JSON
@load policy/tuning/json-logs.zeek

# Redefiniciones
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 0secs;
