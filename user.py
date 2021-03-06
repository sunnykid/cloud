#-*-coding:utf-8-*-

# 사용자 계정별 정책을 호출하는 코드

import boto3
import json
import csv
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

session = boto3.Session()

def find_user():
      f = open('policy.csv','w',encoding='utf-8',newline='')
      wr = csv.writer(f)

      iam = session.client('iam',verify=False)

      iamdetaillist=iam.get_account_authorization_details(Filter=["User"])

      wr.writerow(["User Name","Group/Policy","Group/Policy Name"])

      for user in iamdetaillist["UserDetailList"]:
          varname=user["UserName"]
          varinlinelist=user["AttachedManagedPolicies"]
          for inline in varinlinelist:
              varpolicyname=inline['PolicyName']
              wr.writerow([varname,"Inline Policy",varpolicyname])
          vargrouplist = user["GroupList"]
          for group in vargrouplist:
              wr.writerow([varname,"Groups",group])
      f.close()

if __name__=='__main__':
  find_user()
