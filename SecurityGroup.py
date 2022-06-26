#-*-coding:utf-8-*-

import boto3
import csv
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

session = boto3.Session()

def get_securitygroup():
    cidr_block = ""
    ip_protocol = ""
    from_port = ""
    to_port = ""
    from_source = ""

    f = open('Security_Group.csv','w',encoding='utf-8',newline='')
    wr = csv.writer(f)

    print("%s,%s,%s,%s,%s,%s,%s,%s" % ("Region","Group-Name","Group-ID","In/Out","Protocol","Port","Source/Destination","Description"))

    wr.writerow(["Region","Group-Name","Group-ID","In/Out","Protocol","Port","Source/Destination","Description"])

    regions = session.get_available_regions('ec2')

    for region in regions:
        ec2_client = session.client('ec2',region,verify=False)

        try:
            vpcs = ec2_client.describe_vpcs()

            sgs = ec2_client.describe_security_groups()["SecurityGroups"]

            for sg in sgs:
                group_name = sg['GroupName']
                group_id = sg['GroupId']

                inbound = sg['IpPermissions']
                for rule in inbound:

                    if rule['IpProtocol'] == "-1":

                        traffic_type = "All Traffic"
                        ip_protocol = "All"
                        to_port = "All"
                    else:
                        ip_protocol = rule['IpProtocol']
                        from_port = rule['FromPort']
                        to_port = rule['ToPort']

                        if to_port == -1:
                            to_port = "N/A"

                        if len(rule['IpRanges']) > 0:
                                for ip_range in rule['IpRanges']:
                                   cidr_block = ip_range['CidrIp']
                                   if 'Description' in ip_range.keys():
                                      desc = ip_range['Description']
                                      wr.writerow([region,group_name,group_id,"Inbound",ip_protocol,to_port,cidr_block,desc])
                                   else:
                                      desc = "No Description"
                                      wr.writerow([region,group_name,group_id,"Inbound",ip_protocol,to_port,cidr_block,desc])
                        if len(rule['Ipv6Ranges']) > 0:
                                for ip_range in rule['Ipv6Ranges']:
                                   cidr_block = ip_range['CidrIpv6']
                                   if 'Description' in ip_range.keys():
                                      desc = ip_range['Description']
                                      wr.writerow([region,group_name,group_id,"Inbound",ip_protocol,to_port,cidr_block,desc])
                                   else:
                                      desc = "No Description"
                                      wr.writerow([region,group_name,group_id,"Inbound",ip_protocol,to_port,cidr_block,desc])

                        if len(rule['UserIdGroupPairs']) > 0:
                           for source in rule['UserIdGroupPairs']:
                             from_source = source['GroupId']
                             wr.writerow([region,group_name,group_id,"Inbound",ip_protocol,to_port,from_source,desc])


                outbound = sg['IpPermissionsEgress']

                for rule in outbound:

                    if rule['IpProtocol'] == "-1":

                        traffic_type = "All Traffic"
                        ip_protocol = "All"
                        to_port = "All"
                    else:
                        ip_protocol = rule['IpProtocol']
                        from_port = rule['FromPort']
                        to_port = rule['ToPort']

                        if to_port == -1:
                            to_port = "N/A"

                        if len(rule['IpRanges']) > 0:
                                for ip_range in rule['IpRanges']:
                                   cidr_block = ip_range['CidrIp']
                                   if 'Description' in ip_range.keys():
                                      desc = ip_range['Description']
                                      wr.writerow([region,group_name,group_id,"Outbound",ip_protocol,to_port,cidr_block,desc])
                        if len(rule['Ipv6Ranges']) > 0:
                                for ip_range in rule['Ipv6Ranges']:
                                   cidr_block = ip_range['CidrIpv6']
                                   if 'Description' in ip_range.keys():
                                      desc = ip_range['Description']
                                      wr.writerow([region,group_name,group_id,"Outbound",ip_protocol,to_port,cidr_block,desc])
                        if len(rule['UserIdGroupPairs']) > 0:
                           for source in rule['UserIdGroupPairs']:
                             from_source = source['GroupId']
                             wr.writerow([region,group_name,group_id,"Outbound",ip_protocol,to_port,from_source,desc])


        except Exception as e:
          print(region + " is Inactive")

    f.close()
if __name__ == "__main__":
  get_securitygroup()
