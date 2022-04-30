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

