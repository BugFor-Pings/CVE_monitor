#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : Pings
# @Time   : 2025-05-15
# @File   : CVE_monitor.py
# -----------------------------------------------
# 融合OSCS1024漏洞库、安天、Tenable微软安全中心、CVE平台的漏洞信息爬取及推送脚本
# -----------------------------------------------

import json
import requests
from datetime import datetime
import hashlib
import os
import logging
import traceback
from logging.handlers import TimedRotatingFileHandler
from abc import ABCMeta, abstractmethod
from lxml import etree  # 导入lxml.etree模块
import re  # 导入re模块
import sqlite3
import time
import yaml
import telegram

# 确保目录存在
PRJ_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(PRJ_DIR, 'log')
CACHE_DIR = os.path.join(PRJ_DIR, 'cache')

# 创建目录
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

# 日志配置
RUN_LOG = os.path.join(LOG_DIR, 'run.log')
ERR_LOG = os.path.join(LOG_DIR, 'err.log')

def init_log(runlog=RUN_LOG, errlog=ERR_LOG):
    """
    初始化日志配置 （只需在程序入口调用一次）
    :return: None
    """
    # 全局配置
    logger = logging.getLogger()
    logger.setLevel("DEBUG")
    BASIC_FORMAT = "%(asctime)s [%(levelname)s] : %(message)s"
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(BASIC_FORMAT, DATE_FORMAT)

    # 输出到控制台的 handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.setLevel("DEBUG")
    logger.addHandler(ch)

    # 输出到运行日志文件的 handler
    fh = TimedRotatingFileHandler(filename=runlog, when="MIDNIGHT", interval=1, backupCount=7)
    fh.setFormatter(formatter)
    fh.setLevel("INFO")
    logger.addHandler(fh)

    # 输出到异常日志文件的 handler
    exfh = TimedRotatingFileHandler(filename=errlog, when="MIDNIGHT", interval=1, backupCount=7)
    exfh.setLevel("ERROR")
    exfh.setFormatter(formatter)
    logger.addHandler(exfh)

    # 禁用第三方日志
    logging.getLogger("requests").setLevel(logging.FATAL)

init_log()

def log_debug(msg):
    """
    打印调试信息
    :param msg: 日志信息
    :return: None
    """
    logging.debug(msg)

def log_info(msg):
    """
    打印正常信息
    :param msg: 日志信息
    :return: None
    """
    logging.info(msg)

def log_warn(msg):
    """
    打印警告信息
    :param msg: 日志信息
    :return: None
    """
    logging.warning(msg)

def log_error(msg):
    """
    打印异常信息和异常堆栈
    :param msg: 日志信息
    :return: None
    """
    logging.exception(msg)
    logging.exception(traceback.format_exc())

class VulnerabilityInfo:
    """
    漏洞信息类
    """

    def __init__(self):
        self.id = ''  # 漏洞唯一标识符
        self.title = ''
        self.time = ''
        self.ids = []
        self.source = ''
        self.detail_url = ''
        self.md5 = ''
        self.cve = ''  # 添加cve属性
        self.src = ''   # 添加src属性

    def is_valid(self):
        return bool(self.title)

    def MD5(self):
        if not self.md5:
            data = '%s%s%s' % (self.title, self.time, self.detail_url)
            self.md5 = hashlib.md5(data.encode(encoding='UTF-8')).hexdigest()
        return self.md5

    def to_msg(self):
        return '\n'.join([
            "\n==============================================",
            "[ 标题 ] %s" % self.title,
            "[ 时间 ] %s" % self.time,
            "[ 编号 ] %s" % ', '.join(self.ids),
            "[ 来源 ] %s" % self.source,
            "[ 详情 ] %s" % self.detail_url
        ])

class CVEInfo(VulnerabilityInfo):
    """
    漏洞信息类
    """

    def __init__(self):
        super().__init__()
        self.info = ''

    def to_msg(self):
        return '\n'.join([
            "\n==============================================",
            "[ 标题  ] %s" % self.title,
            "[ 时间  ] %s" % self.time,
            "[ 编号  ] %s" % self.cve,
            "[ 来源  ] %s" % self.source,
            "[ 详情  ] %s" % self.detail_url
        ])

class BaseCrawler:
    """
    爬虫基类
    """
    __metaclass__ = ABCMeta  # 定义为抽象类

    def __init__(self, timeout=60, charset='utf-8'):
        self.timeout = timeout or 60
        self.charset = charset or 'utf-8'

    @abstractmethod
    def NAME_CH(self):
        return '未知'

    @abstractmethod
    def NAME_EN(self):
        return 'unknown'

    def headers(self):
        return {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
        }

    def vulnerabilities(self):
        log_info('++++++++++++++++++++++++++++++++++++++++++++')
        log_info('正在获取 [%s] 漏洞信息...' % self.NAME_CH())

        try:
            # 获取新的漏洞信息
            new_vulnerabilities = self.get_vulnerabilities()
            
            # 每次获取当前日期，确保日期变化时能获取新的漏洞
            target_date = datetime.now().strftime('%Y-%m-%d')
            log_info(f'使用目标日期: {target_date} 过滤漏洞信息')
            
            # 过滤指定日期的漏洞
            filtered_vulnerabilities = self.filter_by_date(new_vulnerabilities, target_date)
        except Exception as e:
            filtered_vulnerabilities = []
            log_error('获取 [%s] 漏洞信息异常: %s' % (self.NAME_CH(), str(e)))

        log_info('得到 [%s] 最新漏洞信息 [%s] 条' % (self.NAME_CH(), len(filtered_vulnerabilities)))
        log_info('--------------------------------------------')
        return filtered_vulnerabilities

    def cves(self):
        log_info('++++++++++++++++++++++++++++++++++++++++++++')
        log_info('正在获取 [%s] 威胁情报...' % self.NAME_CH())

        try:
            # 获取新的威胁情报
            new_cves = self.get_cves()
            
            # 过滤已经存在于数据库中的威胁情报
            filtered_cves = []
            for cve in new_cves:
                if hasattr(cve, 'id') and cve.id and not is_vulnerability_exists(cve.id):
                    filtered_cves.append(cve)
                    log_info(f"发现新威胁情报：{cve.title}，ID：{cve.id}")
                else:
                    if hasattr(cve, 'title'):
                        log_info(f"威胁情报已存在于数据库中，跳过：{cve.title}")
            
            log_info(f'得到 [{self.NAME_CH()}] 新增威胁情报 [{len(filtered_cves)}/{len(new_cves)}] 条')
        except Exception as e:
            filtered_cves = []
            log_error('获取 [%s] 威胁情报异常: %s' % (self.NAME_CH(), str(e)))

        log_info('--------------------------------------------')
        return filtered_cves

    @abstractmethod
    def get_vulnerabilities(self):
        return []

    @abstractmethod
    def get_cves(self):
        try:
            # 获取 RSS 数据
            response = requests.get(self.rss_url)
            data = response.content
            
            # 解析 RSS 数据
            rss = etree.XML(data)
            
            # 提取漏洞信息
            cves = []
            for item in rss.xpath('//item'):
                title = item.xpath('./title/text()')[0]
                link = item.xpath('./link/text()')[0]
                pub_date = item.xpath('./pubDate/text()')[0]
                
                # 格式化时间
                # time_struct = time.strptime(pub_date, '%a, %d %b %Y %H:%M:%S %Z')
                # formatted_time = time.strftime('%Y-%m-%d %H:%M:%S', time_struct)
                
                # 提取 CVE ID
                cve_id = title.split(' ')[0]
                
                cves.append({
                    'title': title,
                    'time': pub_date,
                    'id': cve_id,
                    'src': 'Tenable',
                    'url': link
                })
            
            return cves
        except Exception as e:
            print(f"获取 Tenable 威胁情报异常: {str(e)}")
            traceback.print_exc()
            return []

    def filter_by_date(self, vulnerabilities, target_date):
        """
        过滤出指定日期的漏洞，并确保不重复推送已经处理过的漏洞
        :param vulnerabilities: 漏洞列表
        :param target_date: 目标日期
        :return: 过滤后的漏洞列表
        """
        filtered = []
        skipped_date = 0
        skipped_exists = 0
        
        for vuln in vulnerabilities:
            # 记录ID和标题用于调试
            vuln_id = getattr(vuln, 'id', '无ID')
            vuln_title = getattr(vuln, 'title', '无标题')
            
            # 首先检查日期是否匹配
            if vuln.time == target_date:
                # 确保ID有效
                if not vuln_id or vuln_id.strip() == '':
                    log_warn(f"漏洞ID无效，跳过: {vuln_title}")
                    skipped_exists += 1
                    continue
                    
                # 检查数据库中是否已经存在此漏洞
                if not is_vulnerability_exists(vuln_id):
                    filtered.append(vuln)
                    log_info(f"发现新漏洞：{vuln_title}，ID：{vuln_id}")
                else:
                    log_info(f"漏洞已存在于数据库中，跳过：{vuln_title}，ID：{vuln_id}")
                    skipped_exists += 1
            else:
                log_info(f"漏洞日期 {vuln.time} 不匹配目标日期 {target_date}，跳过：{vuln_title}")
                skipped_date += 1
                
        # 记录过滤结果
        if skipped_date > 0 or skipped_exists > 0:
            log_info(f"日期筛选: 跳过 {skipped_date} 条非当天漏洞，跳过 {skipped_exists} 条已存在漏洞，保留 {len(filtered)} 条新漏洞")
            
        return filtered

class OSCS1024Crawler(BaseCrawler):
    """
    OSCS1024漏洞库爬虫
    """

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = 'OSCS1024漏洞库'
        self.name_en = 'OSCS1024 Vulnerability Database'
        self.url = 'https://www.oscs1024.com/oscs/v1/vdb/vuln_info'

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def get_vulnerabilities(self):
        response = requests.get(
            self.url,
            headers=self.headers(),
            timeout=self.timeout
        )

        vulnerabilities = []
        if response.status_code == 200:
            data = response.json()
            for item in data:
                vulnerability = self.to_vulnerability(item)
                if vulnerability.is_valid():
                    vulnerabilities.append(vulnerability)
        else:
            log_warn('获取 [%s] 漏洞信息失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
        return vulnerabilities

    def to_vulnerability(self, item):
        vulnerability = VulnerabilityInfo()
        vulnerability.id = item.get('id', '')
        
        # 如果id为空，生成一个唯一ID
        if not vulnerability.id:
            # 使用标题和时间生成MD5作为ID
            title = item.get('title', '')
            time_str = item.get('published_time', '')
            
            # 提取编号作为备选ID
            cnvd_id = item.get('cnvd_id', '')
            cve_id = item.get('cve_id', '')
            mps_id = item.get('mps_id', '')
            
            # 优先使用CVE编号作为ID
            if cve_id:
                vulnerability.id = cve_id
                log_info(f"使用CVE编号作为ID: {cve_id}")
            elif cnvd_id:
                vulnerability.id = cnvd_id
                log_info(f"使用CNVD编号作为ID: {cnvd_id}")
            elif mps_id:
                vulnerability.id = mps_id
                log_info(f"使用MPS编号作为ID: {mps_id}")
            elif title:
                # 如果没有任何编号，则使用标题和时间生成稳定的哈希作为ID
                # 移除时间戳，因为时间戳会导致每次生成不同的ID
                unique_str = f"{title}-{time_str}"
                vulnerability.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
                log_info(f"生成固定哈希ID: {vulnerability.id} (基于标题和发布时间)")
            else:
                # 最后的备选方案，使用固定前缀和当前日期
                current_date = datetime.now().strftime('%Y-%m-%d')
                unique_str = f"oscs1024-unknown-{current_date}"
                vulnerability.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
                log_info(f"生成默认ID: {vulnerability.id} (基于当前日期)")
                
        vulnerability.title = item.get('title', '')
        vulnerability.time = item.get('published_time', '')
        
        # 提取编号
        cnvd_id = item.get('cnvd_id', '')
        cve_id = item.get('cve_id', '')
        mps_id = item.get('mps_id', '')
        
        # 按优先级组合编号
        ids = []
        if cnvd_id:
            ids.append(cnvd_id)
        if cve_id:
            ids.append(cve_id)
        if mps_id:
            ids.append(mps_id)
        vulnerability.ids = ids
        
        # 设置cve属性
        vulnerability.cve = cve_id if cve_id else ''
        vulnerability.src = self.name_ch  # 设置来源
        
        vulnerability.source = 'OSCS1024漏洞库'
        
        # 提取详情链接
        reference_urls = item.get('reference_url_list', [])
        if reference_urls:
            vulnerability.detail_url = reference_urls[0].get('url', '')
        else:
            vulnerability.detail_url = ''
        
        # 记录日志，帮助调试ID重复问题
        log_info(f"处理OSCS1024漏洞: {vulnerability.title}, ID: {vulnerability.id}")
        
        return vulnerability

class AntiYCloud(BaseCrawler):
    """
    安天爬虫
    """

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '安天(antiycloud)'
        self.name_en = 'antiycloud'
        self.home_page = 'https://www.antiycloud.com/'
        self.url = 'https://www.antiycloud.com/api/safeNoticeDetail/{}'

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def get_cves(self):
        try:
            # 获取当前日期，格式为YYYYMMDD，确保每次使用最新日期
            current_date = datetime.now().strftime("%Y%m%d")
            log_info(f"[{self.NAME_CH()}] 使用当前日期 {current_date} 获取安天威胁情报")
            
            # 构造API URL
            api_url = self.url.format(current_date)
            
            # 发送GET请求
            response = requests.get(api_url, headers=self.headers(), timeout=self.timeout)
            
            if response.status_code == 200:
                # 解析JSON数据
                data = response.json()
                
                # 检查status是否为success
                if data.get("status") == "success":
                    # 提取威胁情报数据
                    intel_data = data.get("data", {})
                    
                    # 提取漏洞信息，从content字段获取所有漏洞
                    vulnerabilities = intel_data.get("content", [])
                    
                    # 筛选并格式化漏洞信息
                    cves = []
                    for vuln in vulnerabilities:
                        log_info(f"处理安天漏洞: {vuln.get('title', '无标题')}")
                        # 从漏洞标题中提取漏洞编号（位于括号内）
                        vuln_title = vuln.get("title", "")
                        cve_info = self.to_cve(vuln, intel_data)
                        if cve_info.is_valid():
                            cves.append(cve_info)
                            log_info(f"提取到漏洞编号: {cve_info.cve}")
                    
                    # 过滤已经存在于数据库的威胁情报
                    filtered_cves = []
                    for cve in cves:
                        if hasattr(cve, 'id') and cve.id and not is_vulnerability_exists(cve.id):
                            filtered_cves.append(cve)
                            log_info(f"发现新安天威胁情报：{cve.title}，ID：{cve.id}")
                        else:
                            if hasattr(cve, 'title'):
                                log_info(f"安天威胁情报已存在于数据库中，跳过：{cve.title}")
                    
                    log_info(f"从安天获取到 {len(filtered_cves)}/{len(cves)} 条新威胁情报")
                    return filtered_cves
                else:
                    log_error(f"API返回状态不是success，状态为：{data.get('status')}")
                    return []
            else:
                log_error(f"API请求失败，状态码：{response.status_code}")
                return []
        except Exception as e:
            log_error(f"获取 [{self.NAME_CH()}] 威胁情报异常: {str(e)}")
            log_error(traceback.format_exc())
            return []

    def to_cve(self, vuln, intel_data):
        """
        将安天API返回的数据转为CVEInfo对象
        :param vuln: 单个漏洞数据
        :param intel_data: 完整情报数据
        :return: CVEInfo对象
        """
        cve = CVEInfo()
        
        # 处理标题，先获取title
        title = vuln.get("title", "")
        log_info(f"正在处理漏洞: {title}")
        
        # 提取ID，如果为空则生成一个
        extracted_id = self.extract_ids_from_title(title)
        log_info(f"从标题 '{title}' 中提取到的ID: {extracted_id}")
        
        if not extracted_id:
            # 生成唯一ID
            time_str = intel_data.get("time", "")
            unique_str = f"{title}-{time_str}-{datetime.now().timestamp()}"
            cve.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
            log_info(f"未找到ID，生成MD5: {cve.id}")
        else:
            cve.id = extracted_id
            log_info(f"使用提取的ID: {extracted_id}")
            
        # 设置基本属性
        cve.title = title
        cve.time = intel_data.get("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        cve.cve = extracted_id
        cve.src = self.NAME_CH()
        
        # 设置URL，使用当前日期而不是固定时间戳
        # 从intel_data中提取日期，格式通常为 "2025-05-15 ..."
        if "time" in intel_data and intel_data["time"]:
            try:
                # 尝试从时间字符串中提取日期部分
                date_part = intel_data["time"].split()[0].replace("-", "")  # "2025-05-15" -> "20250515"
                cve.url = f"https://www.antiycloud.com/#/infodetail/{date_part}"
            except Exception:
                # 如果提取失败，使用当前日期
                current_date = datetime.now().strftime("%Y%m%d")
                cve.url = f"https://www.antiycloud.com/#/infodetail/{current_date}"
        else:
            # 如果没有时间信息，使用当前日期
            current_date = datetime.now().strftime("%Y%m%d")
            cve.url = f"https://www.antiycloud.com/#/infodetail/{current_date}"
            
        cve.detail_url = cve.url  # 确保 detail_url 有值
        cve.source = self.NAME_CH()
        
        # 尝试提取漏洞描述
        try:
            if "body" in vuln and isinstance(vuln["body"], list):
                for section in vuln["body"]:
                    if section.get("subtitle") == "一、漏洞描述：":
                        content_list = section.get("content", [])
                        description_texts = []
                        for content_item in content_list:
                            if content_item.get("type") == "text":
                                description_texts.append(content_item.get("data", ""))
                        if description_texts:
                            cve.info = " ".join(description_texts)
        except Exception as e:
            log_error(f"提取漏洞描述时出错: {e}")
            cve.info = f"漏洞标题: {title}"
        
        return cve
        

    def extract_ids_from_title(self, title):
        """
        从标题中提取漏洞编号（括号内的内容）
        :param title: 漏洞标题，例如"1 Tenda AC9命令注入漏洞（CVE-2025-45042）"
        :return: 提取到的漏洞编号，例如"CVE-2025-45042"
        """
        # 使用正则表达式提取标题中括号内的内容
        ids = re.findall(r'（(.*?)）|\((.*?)\)', title)
        # 处理正则表达式结果，ids可能是[('CVE-2025-45042', '')] 或 [('', 'CVE-2025-45042')]形式
        result = []
        for id_pair in ids:
            # 检查每个分组是否有值，取非空的那个
            for id_val in id_pair:
                if id_val:
                    result.append(id_val)
        
        # 返回结果
        return ', '.join(result) if result else ""

class Tenable(BaseCrawler):
    """
    Tenable 漏洞信息爬虫
    """

    def __init__(self):
        """
        初始化
        """
        super().__init__(timeout=60)
        self.url = 'https://www.tenable.com/cve/feeds?sort=newest'

    def NAME_CH(self):
        return 'Tenable (Nessus)'

    def NAME_EN(self):
        return 'Tenable'

    def get_cves(self, limit=10):
        response = requests.get(
            self.url,
            headers=self.headers(),
            timeout=self.timeout
        )

        cves = []
        if response.status_code == 200:
            data = ''.join(response.text.split('\n')[1:])
            rss = etree.XML(data)
            items = rss.xpath("//item")

            cnt = 0
            for item in items:
                cve = self.to_cve(item)
                if cve.is_valid():
                    if cnt < limit:
                        cves.append(cve)
                        cnt += 1
        else:
            log_warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
        return cves

    def to_cve(self, item):
        cve = CVEInfo()
        
        # 获取ID，如果为空则生成一个唯一ID
        title_text = item.xpath("./title")[0].text if item.xpath("./title") else ""
        if title_text:
            cve.id = title_text
        else:
            # 生成一个唯一ID
            _time = item.xpath("./pubDate")[0].text if item.xpath("./pubDate") else ""
            unique_str = f"tenable-{_time}-{datetime.now().timestamp()}"
            cve.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
            
        cve.title = title_text if title_text else "Tenable漏洞"
        cve.src = self.NAME_CH()
        
        link_text = item.xpath("./link")[0].text if item.xpath("./link") else ""
        cve.url = link_text if link_text else ""
        cve.detail_url = cve.url  # 确保 detail_url 有值

        _time = item.xpath("./pubDate")[0].text if item.xpath("./pubDate") else ""
        if _time:
            try:
                cve.time = datetime.strptime(_time, '%a, %d %b %Y %H:%M:%S GMT').strftime('%Y-%m-%d %H:%M:%S')
            except:
                cve.time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        else:
            cve.time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 提取描述信息
        if item.xpath("./description"):
            _desc = item.xpath("./description")[0].text
            _desc = _desc.replace('\r', '').replace('\n', '') if _desc else ""
            try:
                cve.info = re.findall(r'Description</h3>\s*<p>(.*?)</p>', _desc, re.DOTALL)[0].strip()
            except:
                cve.info = _desc
            cve.title = cve.info if cve.info else cve.title
        else:
            cve.info = cve.title
            
        cve.source = self.NAME_CH()
        return cve

class MicrosoftSecurityCrawler(BaseCrawler):
    """
    微软安全响应中心漏洞信息爬虫
    """

    def __init__(self):
        """
        初始化
        """
        super().__init__(timeout=60)
        self.ms_url = 'https://api.msrc.microsoft.com/sug/v2.0/zh-CN/vulnerability'

    def NAME_CH(self):
        return '微软安全响应中心'

    def NAME_EN(self):
        return 'Microsoft Security'

    def get_vulnerabilities(self):
        """虚拟实现，不使用"""
        return []

    def get_cves(self):
        """
        获取微软安全响应中心最新漏洞信息
        :return: 漏洞信息列表
        """
        try:
            log_info("正在从微软安全响应中心获取数据...")
            header = {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
                'Connection': 'keep-alive',
            }
            
            response = requests.get(self.ms_url, headers=header, timeout=self.timeout)
            
            if response.status_code != 200:
                log_error(f"微软安全响应中心API请求失败，状态码: {response.status_code}")
                return []
                
            json_data = response.json()
            
            if '@odata.count' in json_data:
                log_info(f"微软安全响应中心API返回数据总量: {json_data['@odata.count']} 条")
            
            # 获取当天日期
            today = datetime.now().strftime('%Y-%m-%d')
            log_info(f"使用当前日期 {today} 过滤微软安全响应中心漏洞")
            
            # 筛选今天发布的漏洞
            all_cves = []
            new_cves = []
            
            if 'value' in json_data:
                for item in json_data['value']:
                    if 'releaseDate' in item:
                        # releaseDate格式如 "2025-03-21T07:00:43Z"，我们只需要比较日期部分
                        release_date = item['releaseDate'].split('T')[0]  # 提取日期部分 "2025-03-21"
                        # 只筛选当天的数据
                        if release_date == today:
                            cve_info = self.to_cve(item)
                            if cve_info.is_valid():
                                all_cves.append(cve_info)
                                
            # 过滤已存在于数据库的漏洞
            for cve in all_cves:
                if not is_vulnerability_exists(cve.id):
                    new_cves.append(cve)
                    log_info(f"发现新的微软漏洞: {cve.title}")
                else:
                    log_info(f"微软漏洞已存在，跳过: {cve.title}")
            
            log_info(f"从微软安全响应中心获取到 {len(new_cves)}/{len(all_cves)} 条新漏洞数据")
            return new_cves
        except Exception as e:
            log_error(f"获取微软安全响应中心数据时出错: {e}")
            return []

    def to_cve(self, item):
        """
        将微软API返回的数据转为CVEInfo对象
        :param item: API返回的单条数据
        :return: CVEInfo对象
        """
        cve = CVEInfo()
        
        # 获取ID，如果为空则生成一个唯一ID
        cve_number = item.get('cveNumber', '')
        if cve_number:
            cve.id = cve_number
        else:
            # 使用标题和时间生成唯一ID
            title = item.get('cveTitle', '无标题')
            release_date = ''
            if 'releaseDate' in item:
                release_date = item['releaseDate'].split('T')[0]
            unique_str = f"ms-{title}-{release_date}-{datetime.now().timestamp()}"
            cve.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
            
        cve.title = item.get('cveTitle', '无标题')
        
        # 处理时间 "2025-03-21T07:00:43Z" -> "2025-03-21"
        if 'releaseDate' in item:
            release_date = item['releaseDate'].split('T')[0]
            cve.time = release_date
        else:
            cve.time = datetime.now().strftime('%Y-%m-%d')
        
        cve.cve = item.get('cveNumber', '无CVE编号')
        cve.src = self.NAME_CH()
        
        # 获取URL
        mitre_url = item.get('mitreUrl', '')
        if mitre_url:
            cve.url = mitre_url
        else:
            cve_number = item.get('cveNumber', '')
            if cve_number:
                cve.url = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_number}"
            else:
                cve.url = "https://msrc.microsoft.com/update-guide/"
                
        cve.detail_url = cve.url  # 确保 detail_url 有值
        cve.source = self.NAME_CH()
        cve.info = item.get('unformattedDescription', item.get('description', '无描述'))
        
        return cve

class OKCVECrawler(BaseCrawler):
    """
    CVE漏洞库爬虫类
    """

    def __init__(self):
        super(OKCVECrawler, self).__init__()
        # CVE漏洞库API地址
        self.json_url = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/deltaLog.json'

    def NAME_CH(self):
        return 'CVE漏洞库'

    def NAME_EN(self):
        return 'OKCVE'

    def get_vulnerabilities(self):
        return []  # 使用get_cves方法获取漏洞信息

    def get_cves(self):
        """
        从CVE漏洞库获取最新CVE信息
        :return: 漏洞信息列表
        """
        try:
            log_info(f"[{self.NAME_CH()}] 开始获取最新CVE信息")
            
            # 从URL获取JSON数据
            response = requests.get(self.json_url)
            response.raise_for_status()  # 检查HTTP错误
            data = response.json()
            
            # 获取当前日期，确保使用最新日期
            current_date = datetime.now().strftime('%Y-%m-%d')
            log_info(f"[{self.NAME_CH()}] 使用当前日期 {current_date} 过滤CVE信息")
            
            all_cve_list = []
            
            # 处理数据
            for entry in data:
                fetch_time = entry.get('fetchTime', '')
                if fetch_time.startswith(f'{current_date}T'):
                    for cve in entry.get('new', []):
                        cve_info = self.to_cve(cve, fetch_time)
                        if cve_info.is_valid():
                            all_cve_list.append(cve_info)
            
            # 过滤已经存在于数据库的CVE
            new_cve_list = []
            for cve_info in all_cve_list:
                if not is_vulnerability_exists(cve_info.id):
                    new_cve_list.append(cve_info)
                    log_info(f"发现新CVE: {cve_info.title}")
                else:
                    log_info(f"CVE已存在，跳过: {cve_info.title}")
            
            log_info(f"[{self.NAME_CH()}] 获取到 {len(new_cve_list)}/{len(all_cve_list)} 条新CVE信息")
            return new_cve_list
        except Exception as e:
            log_error(f"[{self.NAME_CH()}] 获取CVE信息失败: {str(e)}")
            return []

    def to_cve(self, cve_data, fetch_time):
        """
        转换CVE数据为CVEInfo对象
        :param cve_data: CVE数据
        :param fetch_time: 抓取时间
        :return: CVEInfo对象
        """
        info = CVEInfo()
        
        # 获取ID，如果为空则生成一个唯一ID
        cve_id = cve_data.get('cveId', '')
        if cve_id:
            info.id = cve_id
        else:
            # 生成唯一ID
            unique_str = f"cve-{fetch_time}-{datetime.now().timestamp()}"
            info.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
            
        # 设置标题
        if cve_id:
            info.title = f"{cve_id}漏洞"
        else:
            info.title = f"未知CVE漏洞-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
        info.time = fetch_time if fetch_time else datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        info.cve = cve_id if cve_id else '未知CVE'
        info.src = self.NAME_CH()
        
        # 设置URL
        cve_org_link = cve_data.get('cveOrgLink', '')
        if cve_org_link:
            info.url = cve_org_link
        elif cve_id:
            info.url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        else:
            info.url = "https://cve.mitre.org/"
            
        info.detail_url = info.url  # 确保 detail_url 有值
        info.source = self.NAME_CH()
        info.info = ''
        return info

# 读取配置文件
def load_config():
    try:
        log_info("开始读取配置文件...")
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
            log_info("配置文件读取成功")
            
            # 检查钉钉配置
            if int(config['all_config']['dingding'][0]['enable']) == 1:
                dingding_webhook = config['all_config']['dingding'][1]['webhook']
                dingding_secretKey = config['all_config']['dingding'][2]['secretKey']
                app_name = config['all_config']['dingding'][3]['app_name']
                log_info(f"启用钉钉推送，webhook长度: {len(dingding_webhook)}, secretKey长度: {len(dingding_secretKey)}")
                return app_name, dingding_webhook, dingding_secretKey
            
            # 检查飞书配置
            elif int(config['all_config']['feishu'][0]['enable']) == 1:
                feishu_webhook = config['all_config']['feishu'][1]['webhook']
                app_name = config['all_config']['feishu'][2]['app_name']
                log_info(f"启用飞书推送，webhook长度: {len(feishu_webhook)}")
                return app_name, feishu_webhook
            
            # 检查Server酱配置
            elif int(config['all_config']['server'][0]['enable']) == 1:
                server_sckey = config['all_config']['server'][1]['sckey']
                app_name = config['all_config']['server'][2]['app_name']
                log_info(f"启用Server酱推送，sckey长度: {len(server_sckey)}")
                return app_name, server_sckey
            
            # 检查PushPlus配置
            elif int(config['all_config']['pushplus'][0]['enable']) == 1:
                pushplus_token = config['all_config']['pushplus'][1]['token']
                app_name = config['all_config']['pushplus'][2]['app_name']
                log_info(f"启用PushPlus推送，token长度: {len(pushplus_token)}")
                return app_name, pushplus_token
            
            # 检查Telegram配置
            elif int(config['all_config']['tgbot'][0]['enable']) == 1:
                tgbot_token = config['all_config']['tgbot'][1]['token']
                tgbot_group_id = config['all_config']['tgbot'][2]['group_id']
                app_name = config['all_config']['tgbot'][3]['app_name']
                log_info(f"启用Telegram推送，token长度: {len(tgbot_token)}, group_id: {tgbot_group_id}")
                return app_name, tgbot_token, tgbot_group_id
            
            # 没有启用任何推送
            elif (int(config['all_config']['tgbot'][0]['enable']) == 0 and
                  int(config['all_config']['feishu'][0]['enable']) == 0 and
                  int(config['all_config']['server'][0]['enable']) == 0 and
                  int(config['all_config']['pushplus'][0]['enable']) == 0 and
                  int(config['all_config']['dingding'][0]['enable']) == 0):
                log_error("配置文件有误, 五个社交软件的enable都为0")
                return None
    except Exception as e:
        log_error(f"读取配置文件失败: {e}")
        log_error(traceback.format_exc())
        return None

# 初始化创建数据库
def create_database():
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    try:
        cur.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                   (id TEXT PRIMARY KEY,
                    title TEXT,
                    time TEXT,
                    source TEXT,
                    detail_url TEXT,
                    cve_ids TEXT)''')
        conn.commit()
    except Exception as e:
        print("创建监控表失败！报错：{}".format(e))
    conn.close()

# 检查漏洞是否已存在
def is_vulnerability_exists(cve_id):
    # 如果ID为空，直接返回True表示已存在，防止插入空ID记录
    if not cve_id or cve_id.strip() == '':
        return True
        
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM vulnerabilities WHERE id = ?", (cve_id,))
        result = cur.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        log_error(f"检查漏洞是否存在时出错：{e}")
        conn.close()
        return False

# 将已过滤的漏洞信息插入到数据库（不再检查是否存在）
def insert_into_sqlite3_without_check(cve_list):
    """
    将漏洞信息插入到数据库并立即推送，不再检查是否存在
    因为调用此函数之前已经过滤掉数据库中存在的记录
    :param cve_list: 漏洞信息列表
    """
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    insert_count = 0
    error_count = 0
    
    # 获取配置信息用于推送
    try:
        config = load_config()
        can_push = bool(config)
        if can_push:
            app_name = config[0]
            log_info(f"获取到推送配置，使用 {app_name} 服务")
        else:
            log_warn("未获取到有效的推送配置，将只进行数据库插入，不推送消息")
    except Exception as e:
        log_error(f"加载推送配置失败: {e}")
        can_push = False
    
    for cve in cve_list:
        try:
            # 确保id不为空且有效
            if hasattr(cve, 'id') and cve.id and cve.id.strip() != '':
                id = cve.id
                title = cve.title if hasattr(cve, 'title') and cve.title else '无标题'
                time = cve.time if hasattr(cve, 'time') and cve.time else datetime.now().strftime('%Y-%m-%d')
                source = cve.src if hasattr(cve, 'src') and cve.src else '未知来源'
                detail_url = getattr(cve, 'detail_url', '')  # 使用 getattr 避免除错
                cve_ids = cve.cve if hasattr(cve, 'cve') and cve.cve else ''
                
                # 插入数据库
                cur.execute("INSERT INTO vulnerabilities (id, title, time, source, detail_url, cve_ids) VALUES (?, ?, ?, ?, ?, ?)",
                           (id, title, time, source, detail_url, cve_ids))
                conn.commit()  # 每插入一条就提交一次，确保数据立即保存
                insert_count += 1
                log_info(f"插入新漏洞成功：{title}")
                
                # 立即推送该条漏洞信息
                if can_push:
                    # 构造推送信息
                    push_text = '发现新漏洞！'
                    
                    # 构造通用链接
                    cve_url = getattr(cve, 'detail_url', '')  # 使用 getattr 避免除错
                    if not cve_url and hasattr(cve, 'cve') and cve.cve:
                        cve_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.cve}"
                    
                    # 获取漏洞编号
                    if hasattr(cve, 'cve') and cve.cve:
                        vuln_id = cve.cve
                    elif hasattr(cve, 'ids') and cve.ids:
                        vuln_id = ', '.join(cve.ids)
                    else:
                        vuln_id = cve.id
                    
                    push_msg = f"漏洞标题：{title}\n漏洞编号：{vuln_id}\n来源：{source}\n时间：{time}"
                    if cve_url:
                        push_msg += f"\n详情链接：{cve_url}"
                    
                    # 根据配置的推送方式发送消息
                    try:
                        push_result = False
                        if app_name == "dingding":
                            push_result = dingding(push_text, push_msg, config[1], config[2])
                            log_info(f"钉钉推送结果: {'成功' if push_result else '失败'} - {title}")
                        elif app_name == "feishu":
                            push_result = feishu(push_text, push_msg, config[1])
                            log_info(f"飞书推送结果: {'成功' if push_result else '失败'} - {title}")
                        elif app_name == "server":
                            push_result = server(push_text, push_msg, config[1])
                            log_info(f"Server酱推送结果: {'成功' if push_result else '失败'} - {title}")
                        elif app_name == "pushplus":
                            push_result = pushplus(push_text, push_msg, config[1])
                            log_info(f"PushPlus推送结果: {'成功' if push_result else '失败'} - {title}")
                        elif app_name == "tgbot":
                            push_result = tgbot(push_text, push_msg, config[1], config[2])
                            log_info(f"Telegram推送结果: {'成功' if push_result else '失败'} - {title}")
                        else:
                            log_warn(f"未知的推送方式: {app_name}")
                    except Exception as e:
                        log_error(f"推送漏洞信息失败：{e}")
                
        except sqlite3.IntegrityError as e:
            # 如果遇到唯一性约束错误，记录日志但不中断程序
            log_warn(f"插入数据时唯一性约束错误（意外情况）：{getattr(cve, 'title', '无标题')}，错误：{e}")
            error_count += 1
        except Exception as e:
            log_error(f"插入数据失败：{e}")
            log_error(traceback.format_exc())
            error_count += 1
    
    conn.close()
    log_info(f"成功插入 {insert_count} 条漏洞记录，失败 {error_count} 条")

# 钉钉推送
from dingtalkchatbot.chatbot import DingtalkChatbot  # 从dingtalkchatbot.chatbot模块导入DingtalkChatbot类

def dingding(text, msg, webhook, secretKey):
    try:
        log_info(f"准备推送钉钉消息，webhook: {webhook[:20]}...，内容长度: {len(msg)}")
        ding = DingtalkChatbot(webhook, secret=secretKey)
        result = ding.send_text(msg='{}\r\n{}'.format(text, msg), is_at_all=False)
        log_info(f"钉钉推送返回结果: {result}")
        
        # 钉钉推送API返回格式: {'errcode': 0, 'errmsg': 'ok'}
        if isinstance(result, dict) and result.get('errcode') == 0:
            log_info("钉钉推送成功")
            return True
        else:
            log_error(f"钉钉推送返回异常结果: {result}")
            return False
    except Exception as e:
        log_error(f"钉钉推送出现异常: {e}")
        log_error(traceback.format_exc())
        return False

# 飞书推送
def feishu(text, msg, webhook):
    try:
        log_info(f"准备推送飞书消息，webhook: {webhook[:20]}...，内容长度: {len(msg)}")
        ding = DingtalkChatbot(webhook)
        result = ding.send_text(msg='{}\r\n{}'.format(text, msg), is_at_all=False)
        log_info(f"飞书推送返回结果: {result}")
        
        if isinstance(result, dict) and result.get('StatusCode') == 0:
            log_info("飞书推送成功")
            return True
        else:
            log_error(f"飞书推送返回异常结果: {result}")
            return False
    except Exception as e:
        log_error(f"飞书推送出现异常: {e}")
        log_error(traceback.format_exc())
        return False

# Server酱推送
def server(text, msg, sckey):
    try:
        log_info(f"准备推送Server酱消息，sckey: {sckey[:8]}...，内容长度: {len(msg)}")
        uri = 'https://sc.ftqq.com/{}.send?text={}&desp={}'.format(sckey, text, msg)
        response = requests.get(uri, timeout=10)
        log_info(f"Server酱推送返回状态码: {response.status_code}, 结果: {response.text[:100]}")
        
        if response.status_code == 200:
            log_info("Server酱推送成功")
            return True
        else:
            log_error(f"Server酱推送失败，状态码: {response.status_code}")
            return False
    except Exception as e:
        log_error(f"Server酱推送出现异常: {e}")
        log_error(traceback.format_exc())
        return False

# PushPlus推送
def pushplus(text, msg, token):
    try:
        log_info(f"准备推送PushPlus消息，token: {token[:8]}...，内容长度: {len(msg)}")
        uri = 'https://www.pushplus.plus/send?token={}&title={}&content={}'.format(token, text, msg)
        response = requests.get(uri, timeout=10)
        log_info(f"PushPlus推送返回状态码: {response.status_code}, 结果: {response.text[:100]}")
        
        if response.status_code == 200:
            result = response.json()
            if result.get('code') == 200:
                log_info("PushPlus推送成功")
                return True
            else:
                log_error(f"PushPlus推送失败，错误信息: {result.get('msg')}")
                return False
        else:
            log_error(f"PushPlus推送失败，状态码: {response.status_code}")
            return False
    except Exception as e:
        log_error(f"PushPlus推送出现异常: {e}")
        log_error(traceback.format_exc())
        return False

# Telegram Bot推送
def tgbot(text, msg, token, group_id):
    try:
        log_info(f"准备推送Telegram消息，token: {token[:8]}...，group_id: {group_id}，内容长度: {len(msg)}")
        bot = telegram.Bot(token='{}'.format(token))
        result = bot.send_message(chat_id=group_id, text='{}\r\n{}'.format(text, msg))
        log_info(f"Telegram推送成功，消息ID: {result.message_id}")
        return True
    except Exception as e:
        log_error(f"Telegram推送出现异常: {e}")
        log_error(traceback.format_exc())
        return False

# 发送漏洞信息到社交工具
def send_alerts(cve_list):
    try:
        config = load_config()
        if not config:
            log_error("加载配置文件失败，无法发送推送")
            return
            
        app_name = config[0]
        log_info(f"使用 {app_name} 服务推送漏洞信息")

        for cve in cve_list:
            # 确保漏洞有ID且不存在于数据库中
            if hasattr(cve, 'id') and cve.id and cve.id.strip() and not is_vulnerability_exists(cve.id):
                text = '有新的漏洞信息！'
                # 构造通用链接
                cve_url = getattr(cve, 'detail_url', '')  # 使用 getattr 避免除错
                if not cve_url and hasattr(cve, 'cve') and cve.cve:
                    cve_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.cve}"
                
                title = getattr(cve, 'title', '无标题')
                src = getattr(cve, 'src', '未知来源')
                time_str = getattr(cve, 'time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                
                # 获取漏洞编号
                if hasattr(cve, 'cve') and cve.cve:
                    vuln_id = cve.cve
                elif hasattr(cve, 'ids') and cve.ids:
                    vuln_id = ', '.join(cve.ids)
                else:
                    vuln_id = cve.id
                
                msg = f"漏洞标题：{title}\n漏洞编号：{vuln_id}\n来源：{src}\n时间：{time_str}"
                if cve_url:
                    msg += f"\n详情链接：{cve_url}"
                
                # 根据配置的推送方式发送消息
                try:
                    if app_name == "dingding":
                        dingding(text, msg, config[1], config[2])
                        log_info(f"成功通过钉钉推送漏洞信息：{title}")
                    elif app_name == "feishu":
                        feishu(text, msg, config[1])
                        log_info(f"成功通过飞书推送漏洞信息：{title}")
                    elif app_name == "server":
                        server(text, msg, config[1])
                        log_info(f"成功通过Server酱推送漏洞信息：{title}")
                    elif app_name == "pushplus":
                        pushplus(text, msg, config[1])
                        log_info(f"成功通过PushPlus推送漏洞信息：{title}")
                    elif app_name == "tgbot":
                        tgbot(text, msg, config[1], config[2])
                        log_info(f"成功通过Telegram推送漏洞信息：{title}")
                except Exception as e:
                    log_error(f"推送漏洞信息失败：{e}")
    except Exception as e:
        log_error(f"发送漏洞推送时出错：{e}")
        log_error(traceback.format_exc())

# 将漏洞信息插入到数据库，并立即推送新发现的漏洞
def insert_into_sqlite3(cve_list):
    """
    将漏洞信息插入到数据库并立即推送
    为保持向后兼容性保留此函数，但现在直接调用无检查版本
    :param cve_list: 漏洞信息列表
    """
    log_info("调用兼容性函数insert_into_sqlite3，内部使用无检查版本")
    # 直接调用无检查版本
    insert_into_sqlite3_without_check(cve_list)

# 主函数
if __name__ == '__main__':
    try:
        # 创建数据库表
        create_database()
        log_info("=== 漏洞监控程序启动 ===")
        
        # 记录上次运行的日期，用于检测日期变化
        last_run_date = datetime.now().strftime('%Y-%m-%d')
        log_info(f"开始运行，当前日期: {last_run_date}")
        
        # 初始化爬虫对象
        oscs1024 = OSCS1024Crawler()
        antiycloud = AntiYCloud()
        tenable = Tenable()
        ms_crawler = MicrosoftSecurityCrawler()
        okcve_crawler = OKCVECrawler()
        
        # 主循环
        while True:
            try:
                # 检查日期是否变化
                current_date = datetime.now().strftime('%Y-%m-%d')
                if current_date != last_run_date:
                    log_info(f"检测到日期变化: {last_run_date} -> {current_date}")
                    last_run_date = current_date
                
                log_info(f"开始新一轮漏洞获取...当前日期: {current_date}")
                all_cves = []
                
                # 获取各个平台的漏洞信息（每个平台的get方法已经确保只返回数据库中不存在的新漏洞）
                try:
                    oscs1024_vulnerabilities = oscs1024.vulnerabilities()
                    if oscs1024_vulnerabilities:
                        all_cves.extend(oscs1024_vulnerabilities)
                        log_info(f"从OSCS1024获取到 {len(oscs1024_vulnerabilities)} 条新漏洞")
                except Exception as e:
                    log_error(f"从OSCS1024获取漏洞失败: {e}")
                
                # 在请求之间添加短暂休眠，防止请求过于频繁
                time.sleep(2)
                
                try:
                    antiycloud_cves = antiycloud.cves()
                    if antiycloud_cves:
                        all_cves.extend(antiycloud_cves)
                        log_info(f"从安天获取到 {len(antiycloud_cves)} 条新漏洞")
                except Exception as e:
                    log_error(f"从安天获取漏洞失败: {e}")
                
                time.sleep(2)
                
                try:
                    tenable_cves = tenable.cves()
                    if tenable_cves:
                        all_cves.extend(tenable_cves)
                        log_info(f"从Tenable获取到 {len(tenable_cves)} 条新漏洞")
                except Exception as e:
                    log_error(f"从Tenable获取漏洞失败: {e}")
                
                time.sleep(2)
                
                try:
                    ms_cves = ms_crawler.get_cves()
                    if ms_cves:
                        all_cves.extend(ms_cves)
                        log_info(f"从微软安全响应中心获取到 {len(ms_cves)} 条新漏洞")
                except Exception as e:
                    log_error(f"从微软安全响应中心获取漏洞失败: {e}")
                
                time.sleep(2)
                
                try:
                    okcve_cves = okcve_crawler.get_cves()
                    if okcve_cves:
                        all_cves.extend(okcve_cves)
                        log_info(f"从CVE漏洞库获取到 {len(okcve_cves)} 条新漏洞")
                except Exception as e:
                    log_error(f"从CVE漏洞库获取漏洞失败: {e}")
                
                log_info(f"本次总共获取到 {len(all_cves)} 条新漏洞信息")
                
                # 将漏洞信息插入数据库（这些都是已经过滤过的新漏洞，所以不用再次检查数据库）
                if all_cves:
                    insert_into_sqlite3_without_check(all_cves)
                else:
                    log_info("本次未获取到任何新漏洞信息")
                
                log_info("本轮漏洞获取完成，等待下一轮...")
                # 每隔5分钟运行一次
                time.sleep(300)
                
            except Exception as e:
                log_error(f"主循环发生异常: {e}")
                log_error(traceback.format_exc())
                # 发生错误时等待1分钟后重试
                time.sleep(60)
                
    except Exception as e:
        log_error(f"程序启动失败: {e}")
        log_error(traceback.format_exc())