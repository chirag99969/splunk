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

