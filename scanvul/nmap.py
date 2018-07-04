import queue
import subprocess
import xml.etree.ElementTree as ET
import threading
import datetime
import os


nse_map = {
    'http-vuln-cve2015-1427': 'nmap -p80 --script http-vuln-cve2017-5638.nse {target} -oX {filename}'
}

vul_name_map = {
    'http-vuln-cve2015-1427': 'CVE2015-1427'
}


class BatchThreads(threading.Thread):
    def __init__(self, url_q, vul, res_q):
        super(BatchThreads, self).__init__()
        self.url_q = url_q
        self.res_q = res_q
        self.vul = vul

    def run(self):
        while True:
            if self.url_q.empty():
                break
            else:
                try:
                    i, url = self.url_q.get()
                    # print(url)
                    nmap(url, i, self.vul, self.res_q)
                    # self.result = verify_holes(url, self.res_q)
                except:
                    break


def nmap(target, i, vul, result_q):
    filename = str(i) + '-' + vul + '.xml'
    command = nse_map[vul].format(target=target, filename=filename)
    subprocess.call([command], shell=True)
    with open(filename, 'r') as f:
        xml = ET.ElementTree(file=f)
    nmap_result = xml.find('//script[@id={vul}]'.format(vul=vul))
    try:
        if 'VULNERABLE' in nmap_result.find('//elem[@key=\'state\']').text:
            now = datetime.datetime.today()
            local_time = now.strftime('%Y-%m-%d %H:%M:%S')
            result_q.put({
                'url': target,
                'hole_name': vul_name_map[vul],
                'info': '',
                'method': '',
                'tc_time': local_time
            })
    except:
        pass
    finally:
        os.remove(filename)


def main(target_list, ex_result_q):
    target_q = queue.Queue()
    result_q = queue.Queue()
    for i, target in enumerate(target_list):
        target_q.put((i, target))
    _thread_num = 1000
    if _thread_num > (target_q.qsize() / 2):
        _thread_num = target_q.qsize()
        print('thread_num:', _thread_num)
    threads = []
    for _ in range(_thread_num):
        for vul in nse_map:
            threads.append(BatchThreads(target_q, vul, result_q))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result_list = []
    while not result_q.empty():
        result_list.append(result_q.get())
    ex_result_q.put(result_list)
    print(result_list)