import boto3
import collections
import datetime
import csv
from time import gmtime, strftime
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders
import os

#Find current owner ID
sts = boto3.client('sts')
identity = sts.get_caller_identity()
ownerId = identity['Account']

#Environment Variables
SES_SMTP_USER=os.environ["SES_SMTP_USER"]
SES_SMTP_PASSWORD=os.environ["SES_SMTP_PASSWORD"]
S3_INVENTORY_BUCKET=os.environ["S3_INVENTORY_BUCKET"]
MAIL_FROM=os.environ["MAIL_FROM"]
MAIL_TO=os.environ["MAIL_TO"]

#Constants
MAIL_SUBJECT="AWS Inventory for " + ownerId
MAIL_BODY=MAIL_SUBJECT + '\n'


#EC2 connection beginning
ec = boto3.client('ec2')
#S3 connection beginning
s3 = boto3.resource('s3')

#lambda function beginning
def lambda_handler(event, context):
    #get to the curren date
    date_fmt = strftime("%Y_%m_%d", gmtime())
    #Give your file path
    filepath ='/tmp/AWS_Resources_' + date_fmt + '.csv'
    #Give your filename
    filename ='AWS_Resources_' + date_fmt + '.csv'
    csv_file = open(filepath,'w+')

    #boto3 library ec2 API describe region page
    #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_regions
    regions = ec.describe_regions().get('Regions',[] )
    for region in regions:
        reg=region['RegionName']
        regname='REGION :' + reg
        #EC2 connection beginning
        ec2con = boto3.client('ec2',region_name=reg)
        #boto3 library ec2 API describe instance page
        #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_instances
        reservations = ec2con.describe_instances().get(
        'Reservations',[]
        )
        instances = sum(
            [
                [i for i in r['Instances']]
                for r in reservations
            ], [])
        instanceslist = len(instances)
        if instanceslist > 0:
            csv_file.write("%s,%s,%s,%s,%s,%s\n"%('','','','','',''))
            csv_file.write("%s,%s\n"%('EC2 INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s,%s\n"%('InstanceID','Instance_State','InstanceName','Instance_Type','LaunchTime','Instance_Placement', 'SecurityGroupsStr'))
            csv_file.flush()

        for instance in instances:
            state=instance['State']['Name']
            if state =='running':
                for tags in instance['Tags']:
                    Instancename= tags['Value']
                    key= tags['Key']
                    if key == 'Name' :
                        instanceid=instance['InstanceId']
                        instancetype=instance['InstanceType']
                        launchtime =instance['LaunchTime']
                        Placement=instance['Placement']['AvailabilityZone']
                        securityGroups = instance['SecurityGroups']
                        securityGroupsStr = ''
                        for idx, securityGroup in enumerate(securityGroups):
                            if idx > 0:
                                securityGroupsStr += '; '
                            securityGroupsStr += securityGroup['GroupName']
                        csv_file.write("%s,%s,%s,%s,%s,%s,%s\n"% (instanceid,state,Instancename,instancetype,launchtime,Placement,securityGroupsStr))
                        csv_file.flush()

        for instance in instances:
            state=instance['State']['Name']
            if state =='stopped':
                for tags in instance['Tags']:
                    Instancename= tags['Value']
                    key= tags['Key']
                    if key == 'Name' :
                        instanceid=instance['InstanceId']
                        instancetype=instance['InstanceType']
                        launchtime =instance['LaunchTime']
                        Placement=instance['Placement']['AvailabilityZone']
                        csv_file.write("%s,%s,%s,%s,%s,%s\n"%(instanceid,state,Instancename,instancetype,launchtime,Placement))
                        csv_file.flush()

        #boto3 library ec2 API describe volumes page
        #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_volumes
        ec2volumes = ec2con.describe_volumes().get('Volumes',[])
        volumes = sum(
            [
                [i for i in r['Attachments']]
                for r in ec2volumes
            ], [])
        volumeslist = len(volumes)
        if volumeslist > 0:
            csv_file.write("%s,%s,%s,%s\n"%('','','',''))
            csv_file.write("%s,%s\n"%('EBS Volume',regname))
            csv_file.write("%s,%s,%s,%s\n"%('VolumeId','InstanceId','AttachTime','State'))
            csv_file.flush()

        for volume in volumes:
            VolumeId=volume['VolumeId']
            InstanceId=volume['InstanceId']
            State=volume['State']
            AttachTime=volume['AttachTime']
            csv_file.write("%s,%s,%s,%s\n" % (VolumeId,InstanceId,AttachTime,State))
            csv_file.flush()

        #boto3 library ec2 API describe snapshots page
        #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_snapshots
        ec2snapshot = ec2con.describe_snapshots(OwnerIds=[
            ownerId,
        ],).get('Snapshots',[])
        ec2snapshotlist = len(ec2snapshot)
        if ec2snapshotlist > 0:
            csv_file.write("%s,%s,%s,%s,%s\n" % ('','','','',''))
            csv_file.write("%s,%s\n"%('EC2 SNAPSHOT',regname))
            csv_file.write("%s,%s,%s,%s,%s\n" % ('SnapshotId','VolumeId','StartTime','VolumeSize','Description'))
            csv_file.flush()

        for snapshots in ec2snapshot:
            SnapshotId=snapshots['SnapshotId']
            VolumeId=snapshots['VolumeId']
            StartTime=snapshots['StartTime']
            VolumeSize=snapshots['VolumeSize']
            Description=snapshots['Description']
            csv_file.write("%s,%s,%s,%s,%s\n" % (SnapshotId,VolumeId,StartTime,VolumeSize,Description))
            csv_file.flush()

        #boto3 library ec2 API describe addresses page
        #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_addresses
        addresses = ec2con.describe_addresses().get('Addresses',[] )
        addresseslist = len(addresses)
        if addresseslist > 0:
            csv_file.write("%s,%s,%s,%s,%s\n"%('','','','',''))
            csv_file.write("%s,%s\n"%('EIPS INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s\n"%('PublicIp','AllocationId','Domain','InstanceId'))
            csv_file.flush()

            for address in addresses:
                PublicIp=address['PublicIp']
                try:
                    AllocationId=address['AllocationId']
                except:
                    AllocationId="empty"
                Domain=address['Domain']
                instanceId=address['InstanceId']
                csv_file.write("%s,%s,%s,%s\n"%(PublicIp,AllocationId,Domain,instanceId))
                csv_file.flush()

        def printSecGroup(groupType, permission):
            ipProtocol = permission['IpProtocol']
            try:
                fromPort = permission['FromPort']
            except KeyError:
                fromPort = None
            try:
                toPort = permission['ToPort']
            except KeyError:
                toPort = None
            try:
                ipRanges = permission['IpRanges']
            except KeyError:
                ipRanges = []
            ipRangesStr = ''
            for idx, ipRange in enumerate(ipRanges):
                if idx > 0:
                    ipRangesStr += '; '
                ipRangesStr += ipRange['CidrIp']
                csv_file.write("%s,%s,%s,%s,%s,%s\n"%(groupName,groupType,ipProtocol,fromPort,toPort,ipRangesStr))
                csv_file.flush()

        #boto3 library ec2 API describe security groups page
        #http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
        securityGroups = ec2con.describe_security_groups(
            Filters = [
                {
                    'Name': 'owner-id',
                    'Values': [
                        ownerId,
                    ]
                }
            ]
        ).get('SecurityGroups')
        if len(securityGroups) > 0:
            csv_file.write("%s,%s,%s,%s,%s\n"%('','','','',''))
            csv_file.write("%s,%s\n"%('SEC GROUPS',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s\n"%('GroupName','GroupType','IpProtocol','FromPort','ToPort','IpRangesStr'))
            csv_file.flush()
            for securityGroup in securityGroups:
                groupName = securityGroup['GroupName']
                ipPermissions = securityGroup['IpPermissions']
                for ipPermission in ipPermissions:
                    groupType = 'ingress'
                    printSecGroup (groupType, ipPermission)
                ipPermissionsEgress = securityGroup['IpPermissionsEgress']
                for ipPermissionEgress in ipPermissionsEgress:
                    groupType = 'egress'
                    printSecGroup (groupType, ipPermissionEgress)



        #RDS Connection beginning
        rdscon = boto3.client('rds',region_name=reg)

        #boto3 library RDS API describe db instances page
        #http://boto3.readthedocs.org/en/latest/reference/services/rds.html#RDS.Client.describe_db_instances
        rdb = rdscon.describe_db_instances().get(
        'DBInstances',[]
        )
        rdblist = len(rdb)
        if rdblist > 0:
            csv_file.write("%s,%s,%s,%s\n" %('','','',''))
            csv_file.write("%s,%s\n"%('RDS INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s\n" %('DBInstanceIdentifier','DBInstanceStatus','DBName','DBInstanceClass'))
            csv_file.flush()

        for dbinstance in rdb:
            DBInstanceIdentifier = dbinstance['DBInstanceIdentifier']
            DBInstanceClass = dbinstance['DBInstanceClass']
            DBInstanceStatus = dbinstance['DBInstanceStatus']
            try:
                DBName = dbinstance['DBName']
            except:
                DBName = "empty"
            csv_file.write("%s,%s,%s,%s\n" %(DBInstanceIdentifier,DBInstanceStatus,DBName,DBInstanceClass))
            csv_file.flush()

        #ELB connection beginning
        elbcon = boto3.client('elb',region_name=reg)

        #boto3 library ELB API describe db instances page
        #http://boto3.readthedocs.org/en/latest/reference/services/elb.html#ElasticLoadBalancing.Client.describe_load_balancers
        loadbalancer = elbcon.describe_load_balancers().get('LoadBalancerDescriptions',[])
        loadbalancerlist = len(loadbalancer)
        if loadbalancerlist > 0:
            csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
            csv_file.write("%s,%s\n"%('ELB INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s\n" % ('LoadBalancerName','DNSName','CanonicalHostedZoneName','CanonicalHostedZoneNameID'))
            csv_file.flush()

        for load in loadbalancer:
            LoadBalancerName=load['LoadBalancerName']
            DNSName=load['DNSName']
            CanonicalHostedZoneName=load['CanonicalHostedZoneName']
            CanonicalHostedZoneNameID=load['CanonicalHostedZoneNameID']
            csv_file.write("%s,%s,%s,%s\n" % (LoadBalancerName,DNSName,CanonicalHostedZoneName,CanonicalHostedZoneNameID))
            csv_file.flush()

    def mail(fromadd,to, subject, text, attach):
       msg = MIMEMultipart()
       msg['From'] = fromadd
       msg['To'] = to
       msg['Subject'] = subject
       msg.attach(MIMEText(text))
       part = MIMEBase('application', 'octet-stream')
       part.set_payload(open(attach, 'rb').read())
       Encoders.encode_base64(part)
       part.add_header('Content-Disposition','attachment; filename="%s"' % os.path.basename(attach))
       msg.attach(part)
       mailServer = smtplib.SMTP("email-smtp.us-east-1.amazonaws.com", 587)
       mailServer.ehlo()
       mailServer.starttls()
       mailServer.ehlo()
       mailServer.login(SES_SMTP_USER, SES_SMTP_PASSWORD)
       mailServer.sendmail(fromadd, to, msg.as_string())
       # Should be mailServer.quit(), but that crashes...
       mailServer.close()

    date_fmt = strftime("%Y_%m_%d", gmtime())
    #Give your file path
    filepath ='/tmp/AWS_Resources_' + date_fmt + '.csv'
    #Save Inventory
    s3.Object(S3_INVENTORY_BUCKET, filename).put(Body=open(filepath, 'rb'))
    #Send Inventory
    mail(MAIL_FROM, MAIL_TO, MAIL_SUBJECT, MAIL_BODY, filepath)

