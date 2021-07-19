import requests
from peewee import *
from datetime import datetime
import time
import random
import dingtalkchatbot.chatbot as cb
import math
db = SqliteDatabase("cve.sqlite")
db_cnvd=SqliteDatabase("cnvd.sqlite")

class CVE_DB(Model):
    id = IntegerField()
    full_name = CharField(max_length=1024)
    description = CharField(max_length=4098)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)

    class Meta:
        database = db

class CNVD_DB(Model):
    id = IntegerField()
    full_name = CharField(max_length=1024)
    description = CharField(max_length=4098)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)

    class Meta:
        database = db_cnvd

db.connect()
db.create_tables([CVE_DB])
db_cnvd.connect()
db_cnvd.create_tables([CNVD_DB])

# 钉钉
def dingding(text, msg):
    # 将此处换为钉钉机器人的api
    webhook = ''
    ding = cb.DingtalkChatbot(webhook)
    ding.send_text(msg = '{}\r\n{}'.format(text, msg), is_at_all=False)

def get_info(year):
    # 监控用的
    count=0
    while True:
        try:
            api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated&per_page=80".format(year)
        # 请求API
            req = requests.get(api).json()
            items = req["items"]
            return items
        except Exception as e:
            if count>5:
                title=r"CVE脚本请求错误超过5次" 
                content='请速速检查脚本'
                dingding(title,content)
            print("CVE网络请求发生错误", e)
            count+=1
            time.sleep(5)
def get_info_cnvd(year):
    # 监控用的
    count=0
    while True:
        try:
            api = "https://api.github.com/search/repositories?q=CNVD-{}&sort=updated&per_page=150".format(year)
        # 请求API
            req = requests.get(api).json()
            items = req["items"]
            return items
        except Exception as e:
            if count>5：
                title=r"CNVD脚本请求错误超过5次"
                content='请速速检查脚本'
                dingding(title,content)
            print("CNVD网络请求发生错误", e)
            count+=1
            time.sleep(5)

def db_match(items):
    r_list = []
    for item in items:
        id = item["id"]
        if CVE_DB.select().where(CVE_DB.id == id).count() != 0 or item["fork"]==True :
            continue
        full_name = item["full_name"]
        description = item["description"]
        if description == "" or description == None:
            description = 'no description'
        else:
            description = description.strip()
        url = item["html_url"]
        created_at = item["created_at"]
        r_list.append({
            "id": id,
            "full_name": full_name,
            "description": description,
            "url": url,
            "created_at": created_at
        })
        CVE_DB.create(id=id,
                      full_name=full_name,
                      description=description,
                      url=url,
                      created_at=created_at)
    return sorted(r_list, key=lambda e: e.__getitem__('created_at'))

def db_match_cnvd(items):
    r_list = []
    for item in items:
        id = item["id"]
        if CNVD_DB.select().where(CNVD_DB.id == id).count() != 0 or item["fork"]==True :
            continue
        full_name = item["full_name"]
        description = item["description"]
        if description == "" or description == None:
            description = 'no description'
        else:
            description = description.strip()
        url = item["html_url"]
        created_at = item["created_at"]
        r_list.append({
            "id": id,
            "full_name": full_name,
            "description": description,
            "url": url,
            "created_at": created_at
        })
        CNVD_DB.create(id=id,
                      full_name=full_name,
                      description=description,
                      url=url,
                      created_at=created_at)
    return sorted(r_list, key=lambda e: e.__getitem__('created_at'))

if __name__ == "__main__":
    print("CVE/CNVD监控中...")
    while True:
        try:
            year = datetime.now().year
            items = get_info(year)
            items_cnvd=get_info_cnvd(year)
            sorted_list=db_match(items)
            sorted_list_cnvd=db_match_cnvd(items_cnvd)
            if len(sorted_list)!=0:
                title = r'有新的CVE送达！'
                temp = ''
                for one in sorted_list:
                    temp += '{' + one["full_name"] + ':' + one["description"] + '(' + one["url"] + ')' + '}' + '\r\n'
                dingding(title, temp)
            if len(sorted_list_cnvd)!=0:
                title_cnvd=r"有新的CNVD送达！"
                temp_cnvd=''
                for one_cnvd in sorted_list_cnvd:
                    temp_cnvd+='{' + one_cnvd["full_name"] + ':' + one_cnvd["description"] + '(' + one_cnvd["url"] + ')' + '}' + '\r\n'
                dingding(title_cnvd,temp_cnvd)
            time.sleep(21600)
        except Exception as e:
            raise e
    # items=get_info(year)
    # sorted_list=db_match(items)
    # title=r'有新的CVE送达！'
    # temp=''
    # for one in sorted_list:
    #     temp+='{'+one["full_name"]+':'+one["description"]+'('+one["url"]+')'+'}'+'\r\n'
    # dingding(title,temp)