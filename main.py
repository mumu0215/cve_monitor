import requests
from peewee import *
from datetime import datetime
import time
import random
import dingtalkchatbot.chatbot as cb
import math
db = SqliteDatabase("cve.sqlite")

class CVE_DB(Model):
    id = IntegerField()
    full_name = CharField(max_length=1024)
    description = CharField(max_length=4098)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)

    class Meta:
        database = db

db.connect()
db.create_tables([CVE_DB])

# 钉钉
def dingding(text, msg):
    # 将此处换为钉钉机器人的api
    webhook = ''
    ding = cb.DingtalkChatbot(webhook)
    ding.send_text(msg = '{}\r\n{}'.format(text, msg), is_at_all=False)

def get_info(year):
    # 监控用的
    try:
        api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated&per_page=80".format(year)
        # 请求API
        req = requests.get(api).json()
        items = req["items"]

        return items
    except Exception as e:
        print("网络请求发生错误", e)
        return None

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

if __name__ == "__main__":
    print("CVE监控中...")
    while True:
        try:
            year = datetime.now().year
            items = get_info(year)
            sorted_list=db_match(items)
            if len(sorted_list)!=0:
                title = r'有新的CVE送达！'
                temp = ''
                for one in sorted_list:
                    temp += '{' + one["full_name"] + ':' + one["description"] + '(' + one["url"] + ')' + '}' + '\r\n'
                dingding(title, temp)
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