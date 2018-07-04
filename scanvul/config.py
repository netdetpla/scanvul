"""
配置信息
"""

# 任务位置文件
CONFIG_FILE = '/tmp/conf/busi.conf'
# 任务状态文件位置
APP_STATUS = '/tmp/appstatus'
# log位置
LOG_FILE = '/tmp/log'
# result位置
RESULT_FILE = '/tmp/result'
# 漏洞类型对应处理
VUL_SCAN_FUNC = {
    '0': 'test',
    '1': 'struts2',
    # '2': 'nmap'
}