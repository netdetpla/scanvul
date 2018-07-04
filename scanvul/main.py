import base64
import os
import json
import traceback
import importlib
import threading
import queue
import codecs

import config
import log
import is_connect
import process

task_id = ''
uuid = ''
task_name = ''
# 白名单(0) or 云平台(1)
platform = ''
target_list = ''
vul_type_list = ''

task_list = {}
result_queue = queue.Queue()


# 漏洞类
class Vulnerability:
    def __init__(self, vul_name, detail):
        self.vul_name = vul_name
        self.detail = detail

    def to_dict(self):
        return {
            'vul_name': self.vul_name,
            'detail': self.detail
        }


# 任务类
class VulTask:
    def __init__(self, target, vul_type):
        self.target = target
        self.vul_list = []
        self.vul_type = vul_type

    def add_vul(self, vul_name, detail):
        self.vul_list.append(Vulnerability(vul_name, detail))

    def to_dict(self):
        vul_dict = []
        for vul in self.vul_list:
            vul_dict.append((vul.to_dict()))
        return {
            'target': self.target,
            'vul_list': vul_dict,
            'type': self.vul_type
        }


# 获取配置
def get_config():
    global task_id
    global task_name
    global platform
    global uuid
    global vul_type_list
    global target_list
    global task_list

    with open(config.CONFIG_FILE, 'r') as f:
        task = str(base64.b64decode(f.read())).split(';')
    task_id = task[0][2:]
    task_name = task[1]
    platform = task[2]
    vul_type_list = task[3].split(',')
    target_list = task[4].split(',')

    uuid = task[5][:-1]

    for single_type in vul_type_list:
        task_list[single_type] = []
        for single_target in target_list:
            task_list[single_type].append(single_target)


# 调用对应模块
def scan_vul():
    global result_queue
    global processer
    mod_threads = []
    for vul_type in task_list:
        t = threading.Thread(
            target=importlib.import_module(config.VUL_SCAN_FUNC[vul_type]).main,
            args=(task_list[vul_type], result_queue, processer)
        )
        mod_threads.append(t)
        t.start()
    for t in mod_threads:
        t.join()


def write_result_on_whitelist_server():
    i = 0
    while not result_queue.empty():
        with codecs.open(os.path.join(config.RESULT_FILE, str(i) + '.result'), 'w', 'utf-8') as f:
            r = result_queue.get()
            r['task_id'] = task_id
            json.dump(r, f, ensure_ascii=False)
        i += 1


def write_result_on_cloud_server():
    with codecs.open(os.path.join(config.RESULT_FILE, task_id + '.result'), 'a', 'utf-8') as f:
        while not result_queue.empty():
            r = result_queue.get()
            r['task_id'] = task_id
            json.dump(r, f, ensure_ascii=False)
            f.write('\n')

if __name__ == '__main__':
    log.task_start()
    try:
        os.makedirs(config.LOG_FILE)
    except FileExistsError:
        pass
    try:
        os.makedirs(config.APP_STATUS)
    except FileExistsError:
        pass
    try:
        os.makedirs(config.RESULT_FILE)
    except FileExistsError:
        pass
    # 判断网络
    is_connect.Update()
    # try:
    #     ex_ip = urllib2.urlopen("http://ip.6655.com/ip.aspx").read().decode()
    # except:
    #     ex_ip = ''
    # if ex_ip is '':
    #     log.task_fail()
    #     log.write_result_fail()
    #     e = 'Can not get external IP address.'
    #     print(e)
    #     log.write_error_to_appstatus(e, 2)
    # 获取配置
    log.get_conf()
    try:
        get_config()
        log.get_conf_success()
    except Exception as e:
        log.get_conf_fail()
        log.write_error_to_appstatus(str(e), -1)
    # 计次初始化
    processer = process.processManager()
    processer.set_taskid(task_id, uuid)
    # 执行任务
    log.task_run()
    try:
        scan_vul()
        log.task_run_success()
    except Exception as e:
        traceback.print_exc()
        log.task_run_fail()
        log.write_error_to_appstatus(str(e), -1)
    # 计次结束
    processer.final_send()
    # 写结果
    log.write_result()
    try:
        if platform == '0':
            write_result_on_whitelist_server()
        else:
            write_result_on_cloud_server()
        log.write_result_success()
    except Exception as e:
        traceback.print_exc()
        log.write_result_fail()
        log.write_error_to_appstatus(str(e), -1)
    log.write_success_to_appstatus()
