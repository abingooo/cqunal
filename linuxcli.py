import os
import requests
import time
import json

def chat_completions():
    url="https://api.zhizengzeng.com/v1/chat/completions"
    api_secret_key = 'sk-zk26f90a8ef46c6589207af1a58b11c4e4a68eca448256d6';  # 你的api_secret_key
    headers = {'Content-Type': 'application/json', 'Accept':'application/json',
               'Authorization': "Bearer "+api_secret_key}
    params = {'user':'张三','model':"gpt-5.2",
              'messages':[{'role':'user', 'content':'1+100='}]};
    r = requests.post(url, json.dumps(params), headers=headers)
    print(r)

if __name__ == "__main__":
    chat_completions()