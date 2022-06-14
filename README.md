# splunk
It consists of all the datasets, SPL Queries I used for demonstrations on my YouTube channel cybersecnerd > splunk playlist

## Splunk AWS Security DAY 1

### eventName (command)
sourcetype=aws_all result.sourcetype=aws:cloudtrail result.userName=web_admin  
| stats count values(result.eventName)

### Leaked Key usage over time 
sourcetype=aws_all result.sourcetype=aws:cloudtrail result.userName=web_admin  
| sort + result._time 
| stats count by result.eventName result.sourceIPAddress result.awsRegion result._time

### Also difference in credential post CreateAccessKey
sourcetype=aws_all result.sourcetype=aws:cloudtrail result.userName=web_admin  
| sort + result._time 
| stats count by result.eventName result.sourceIPAddress result.awsRegion result._time result.userIdentity.arn result.userIdentity.accessKeyId

### Successful events
sourcetype=aws_all result.sourcetype=aws:cloudtrail result.userName=web_admin  result.errorCode=success
| sort + result._time 
| stats count by result.eventName result.sourceIPAddress result.awsRegion result._time result.userIdentity.arn result.userIdentity.accessKeyId result.errorCode

### Elaborating GetCallerIdentity
sourcetype=aws_all result.sourcetype=aws:cloudtrail result.eventName=GetCallerIdentity result.userName!=splunk_access
| stats count values(result.userIdentity.accessKeyId) values(result.userIdentity.arn) values(result.responseElements.*) as * by result.userName result.sourceIPAddress

### Making S3 bucket public
sourcetype=aws_all result.sourcetype=aws:cloudtrail result.eventSource=s3* 
| search NOT result.eventName IN (Des*, List*, Get*)
|  stats count values(result.eventName) by result.userIdentity.arn result.sourceIPAddress


## Splunk AWS Security DAY 2

### S3 bucket made Public
sourcetype=aws_all result.sourcetype=aws:cloudtrail result.eventSource=s3* 
| search NOT result.eventName IN (Des*, List*, Get*) 
| stats count by result.eventName result.sourceIPAddress result.userIdentity.arn result.requestParameters.bucketName result._time

### Bucket activity post exposure
sourcetype=aws_all result.sourcetype=aws:s3:accesslogs result.bucket_name=frothlywebcode result.operation IN ("*ACL", "*OBJECT", "*BUCKETPOLICY")
| table result._time result.remote_ip result.requester result.operation result.http_status result.key result.error_code result.bytes_sent result.object_size result.request_uri 
| sort + result._time

## Splunk - Making sense of VPC Flow logs 

### Traffic in outbound direction 

sourcetype=aws_all "result.sourcetype"="aws:cloudwatchlogs:vpcflow" 
| search NOT result.dest_ip IN (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12) 
| stats count values(result.src_ip) values(result.dest_port) values(result.protocol) sum(result.bytes) as bytes sum(result.packets) as packets by result.dest_ip 
| sort -bytes


### Traffic in inbound direction
sourcetype=aws_all "result.sourcetype"="aws:cloudwatchlogs:vpcflow" result.action=blocked
| search NOT result.src_ip IN (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12) 
| stats count values(result.dest_ip) values(result.src_port) values(result.dest_port) values(result.protocol) sum(result.bytes) as bytes sum(result.packets) as packets by result.src_ip result.action
| sort - bytes result.action

### Guarduty Findings 
details 
external IP: 13.125.33.130 (i.e. Brute force, Scanner) , aws_account_id:622676721278, internal IP:172.16.0.178

### RARE Countries 
sourcetype=aws_all "result.sourcetype"="aws:cloudwatchlogs:vpcflow" result.action=blocked
| search NOT result.src_ip IN (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12) 
| iplocation result.src_ip
| rare Country

### Going further
sourcetype=aws_all "result.sourcetype"="aws:cloudwatchlogs:vpcflow" 
| search NOT result.src_ip IN (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12) 
| iplocation result.src_ip
| search Country IN (Armenia, Cambodia, Cyprus, Estonia, "El Salvador", Iraq, Kenya, Jamaica) 
| table result.src_ip result.dest_ip result.action result.src_port result.protocol Country result._time

### All Connection Attempts Over Time To Amp Ports
sourcetype=aws_all "result.sourcetype"="aws:cloudwatchlogs:vpcflow" result.dest_port IN (17, 123, 110, 111, 53, 1812, 1645, 19, 1813, 1646, 161, 162, 389, 69) 
| timechart span=5m count(result.src_ip) by result.dest_port


### Anomaly detection (Malicious IP scanning all the open ports)
sourcetype=aws_all "result.sourcetype"="aws:cloudwatchlogs:vpcflow" result.action=blocked
| search NOT result.src_ip IN (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12) 
| bin span=5m result._time 
| stats count sum(result.bytes) as bytes sum(result.packets) as packets by result.src_ip result.dest_ip result.action result.dest_port result.protocol
| eventstats avg(bytes) as avgbytes stdev(bytes) as stdevbytes 
| eval a=3 
| eval isOutlier=if(bytes > avgbytes + (stdevbytes*3), 1, 0) 
| search isOutlier=1 
| table result.src_ip result.dest_ip result.dest_port  result.protocol result.action
